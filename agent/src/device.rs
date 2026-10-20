//! Read-only Windows Get-Disk enumeration. No raw disk handles or modification APIs.
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// Ephemeral opaque identifier for UI selection only. Never a write authority.
    pub id: String,
    pub model: String,
    pub capacity_bytes: u64,
    pub bus_type: String,
    pub partition_style: String,
    pub read_only: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
pub enum DiscoveryError {
    Unsupported,
    Unavailable(String),
}
impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => {
                f.write_str("Device discovery is currently supported only on Windows")
            }
            Self::Unavailable(msg) => write!(f, "Windows disk inventory unavailable: {msg}"),
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsDisk {
    number: u32,
    #[serde(default)]
    friendly_name: Option<String>,
    #[serde(default)]
    bus_type: Option<String>,
    size: u64,
    #[serde(default)]
    is_boot: bool,
    #[serde(default)]
    is_system: bool,
    #[serde(default)]
    is_offline: bool,
    #[serde(default)]
    is_read_only: bool,
    #[serde(default)]
    partition_style: Option<String>,
    #[serde(default)]
    unique_id: Option<String>,
}

// Get-Disk is a fixed, OS-provided read-only Storage cmdlet; output is JSON.
// Avoid command interpolation, user-defined scripts, and disk modification cmdlets.
#[cfg(windows)]
const READ_ONLY_WINDOWS_INVENTORY: &str = "$ErrorActionPreference='Stop'; Get-Disk | Select-Object Number,FriendlyName,@{Name='BusType';Expression={$_.BusType.ToString()}},Size,IsBoot,IsSystem,IsOffline,IsReadOnly,@{Name='PartitionStyle';Expression={$_.PartitionStyle.ToString()}},UniqueId | ConvertTo-Json -Compress -Depth 3";

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_windows_inventory(json: &str) -> Result<Vec<Device>, DiscoveryError> {
    let input: serde_json::Value = serde_json::from_str(json)
        .map_err(|_| DiscoveryError::Unavailable("invalid disk enumeration JSON".to_string()))?;
    let disks = match input {
        serde_json::Value::Array(entries) => entries,
        serde_json::Value::Object(_) => vec![input],
        serde_json::Value::Null => vec![],
        _ => {
            return Err(DiscoveryError::Unavailable(
                "unexpected disk enumeration shape".to_string(),
            ));
        }
    };
    let mut result = Vec::new();
    for entry in disks {
        let disk: WindowsDisk = serde_json::from_value(entry)
            .map_err(|_| DiscoveryError::Unavailable("invalid disk metadata".to_string()))?;
        // Safest early profile: only explicitly USB, non-boot/non-system, online drives.
        // Internal and ambiguous devices are excluded, even if the UI requested fixed disks.
        if disk.bus_type.as_deref() != Some("USB")
            || disk.is_boot
            || disk.is_system
            || disk.is_offline
            || disk.size == 0
        {
            continue;
        }
        // UniqueId may be absent or duplicated; opaque ID is for display only.
        // It must NEVER be used as a write authorisation/physical handle.
        let unique = disk.unique_id.as_deref().unwrap_or("");
        let id = format!(
            "usb-{}-{}-{}-{}",
            disk.number,
            disk.size,
            unique.len(),
            disk.bus_type.as_deref().unwrap_or("")
        );
        result.push(Device {
            id,
            model: disk
                .friendly_name
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "USB storage".to_string()),
            capacity_bytes: disk.size,
            bus_type: "USB".to_string(),
            partition_style: disk
                .partition_style
                .unwrap_or_else(|| "Unknown".to_string()),
            read_only: disk.is_read_only,
        });
    }
    result.sort_by(|a, b| a.model.cmp(&b.model).then(a.id.cmp(&b.id)));
    Ok(result)
}

#[cfg(windows)]
pub async fn discover() -> Result<Vec<Device>, DiscoveryError> {
    use tokio::{
        process::Command,
        time::{Duration, timeout},
    };
    let child = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            READ_ONLY_WINDOWS_INVENTORY,
        ])
        .kill_on_drop(true)
        .output();
    let output = timeout(Duration::from_secs(10), child)
        .await
        .map_err(|_| DiscoveryError::Unavailable("disk enumeration timed out".to_string()))?
        .map_err(|_| {
            DiscoveryError::Unavailable("PowerShell Storage cmdlets are unavailable".to_string())
        })?;
    if !output.status.success() {
        return Err(DiscoveryError::Unavailable("Get-Disk failed".to_string()));
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err(DiscoveryError::Unavailable(
            "disk enumeration response exceeds limit".to_string(),
        ));
    }
    let json = String::from_utf8(output.stdout)
        .map_err(|_| DiscoveryError::Unavailable("invalid output encoding".to_string()))?;
    parse_windows_inventory(&json)
}

#[cfg(not(windows))]
pub async fn discover() -> Result<Vec<Device>, DiscoveryError> {
    Err(DiscoveryError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_unprotected_usb_is_returned() {
        let json = r#"[
          {"Number":0,"FriendlyName":"System","BusType":"USB","Size":100000,"IsBoot":true,"IsSystem":true,"IsOffline":false},
          {"Number":1,"FriendlyName":"Internal NVMe","BusType":"NVMe","Size":200000,"IsBoot":false,"IsSystem":false,"IsOffline":false},
          {"Number":2,"FriendlyName":"USB Stick","BusType":"USB","Size":32000000000,"IsBoot":false,"IsSystem":false,"IsOffline":false,"IsReadOnly":false,"PartitionStyle":"GPT"},
          {"Number":3,"FriendlyName":"Offline USB","BusType":"USB","Size":32000000000,"IsBoot":false,"IsSystem":false,"IsOffline":true}
        ]"#;
        let drives = parse_windows_inventory(json).unwrap();
        assert_eq!(drives.len(), 1);
        assert_eq!(drives[0].model, "USB Stick");
        assert_eq!(drives[0].capacity_bytes, 32000000000);
    }
    #[test]
    fn handles_single_disk_object_and_null() {
        assert_eq!(parse_windows_inventory("null").unwrap().len(), 0);
        assert_eq!(
            parse_windows_inventory(r#"{"Number":1,"BusType":"USB","Size":1000}"#)
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn malformed_input_fails_closed() {
        assert!(parse_windows_inventory("not-json").is_err());
        assert!(parse_windows_inventory(r#"[{"BusType":"USB"}]"#).is_err());
        assert_eq!(
            parse_windows_inventory(r#"[{"Number":1,"BusType":"SATA","Size":50}]"#)
                .unwrap()
                .len(),
            0
        );
    }
}
