//! Read-only Windows Storage discovery and conservative candidate classification.
//!
//! This is a DISPLAY inventory, not a privileged disk-selection or write policy.
//! A future helper MUST re-enumerate the physical disk, its volumes and OS ancestry
//! inside an independent privileged boundary immediately before opening any handle.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt, sync::LazyLock};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// Process-scoped opaque display ID, not a physical-disk handle or authorization.
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
    #[cfg_attr(windows, allow(dead_code))]
    Unsupported,
    Unavailable(String),
}
impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("Device discovery is supported only on Windows"),
            Self::Unavailable(msg) => write!(f, "Windows disk inventory unavailable: {msg}"),
        }
    }
}

#[derive(Debug, Deserialize)]
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
    #[serde(default)]
    serial_number: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    partition_safety_known: bool,
    #[serde(default)]
    has_protected_partition: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exclusion {
    NotUsb,
    SystemOrBoot,
    OfflineOrEmpty,
    PartitionSafetyUnknown,
    ProtectedPartition,
    IdentityUnknown,
    IdentityCollision,
}

#[derive(Debug)]
struct Candidate<'a> {
    disk: &'a WindowsDisk,
    identity: String,
}

/// The path identifies a Windows storage PnP route; the second independent
/// identifier is the physical serial or on-disk unique ID. Either alone can
/// be reused or spoofed. These are still hints, NOT sufficient write authority.
fn identity_part(raw: Option<&str>) -> Option<String> {
    let normalized = raw?.trim().to_ascii_lowercase();
    if normalized.is_empty() || matches!(normalized.as_str(), "0" | "unknown" | "none" | "null") {
        return None;
    }
    Some(normalized)
}

fn candidate(disk: &WindowsDisk) -> Result<Candidate<'_>, Exclusion> {
    if disk.bus_type.as_deref() != Some("USB") {
        return Err(Exclusion::NotUsb);
    }
    if disk.is_boot || disk.is_system {
        return Err(Exclusion::SystemOrBoot);
    }
    if disk.is_offline || disk.size == 0 {
        return Err(Exclusion::OfflineOrEmpty);
    }
    // Get-Disk's IsBoot/IsSystem can differ from partition flags. The failure
    // to enumerate Get-Partition must never be interpreted as "no system volume".
    if !disk.partition_safety_known {
        return Err(Exclusion::PartitionSafetyUnknown);
    }
    if disk.has_protected_partition {
        return Err(Exclusion::ProtectedPartition);
    }
    let path = identity_part(disk.path.as_deref()).ok_or(Exclusion::IdentityUnknown)?;
    let serial = identity_part(disk.serial_number.as_deref());
    let unique = identity_part(disk.unique_id.as_deref());
    if serial.is_none() && unique.is_none() {
        return Err(Exclusion::IdentityUnknown);
    }
    // Length-prefix fields to make concatenation unambiguous. DiskNumber is
    // intentionally excluded: Windows may reuse it when the drive is swapped.
    let identity = [path, serial.unwrap_or_default(), unique.unwrap_or_default()]
        .iter()
        .map(|s| format!("{}:{s}", s.len()))
        .collect::<Vec<_>>()
        .join("|");
    Ok(Candidate { disk, identity })
}

static PROCESS_SALT: LazyLock<[u8; 32]> = LazyLock::new(rand::random);

fn opaque_id(identity: &str, capacity: u64, salt: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(salt);
    digest.update(identity.as_bytes());
    digest.update(capacity.to_le_bytes());
    let bytes = digest.finalize();
    // 128-bit, salted, collision-resistant display token. Never a security
    // capability and never safe to persist into a future privileged operation.
    format!("usb-{}", hex::encode(&bytes[..16]))
}

fn parse_with_salt(json: &str, salt: &[u8; 32]) -> Result<Vec<Device>, DiscoveryError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|_| DiscoveryError::Unavailable("invalid disk enumeration JSON".into()))?;
    let rows = match value {
        serde_json::Value::Array(rows) => rows,
        serde_json::Value::Object(_) => vec![value],
        serde_json::Value::Null => vec![],
        _ => {
            return Err(DiscoveryError::Unavailable(
                "unexpected disk enumeration shape".into(),
            ));
        }
    };
    if rows.len() > 512 {
        return Err(DiscoveryError::Unavailable(
            "disk inventory limit exceeded".into(),
        ));
    }
    let mut disks = Vec::with_capacity(rows.len());
    for row in rows {
        let disk: WindowsDisk = serde_json::from_value(row)
            .map_err(|_| DiscoveryError::Unavailable("invalid disk metadata".into()))?;
        disks.push(disk);
    }

    // Duplicate disk indices, or duplicate composite identities (often from
    // cloned/unstable Storage provider responses), are NEVER silently accepted.
    let mut index_counts = HashMap::<u32, usize>::new();
    let mut identity_counts = HashMap::<String, usize>::new();
    for disk in &disks {
        *index_counts.entry(disk.number).or_default() += 1;
        if let Ok(hit) = candidate(disk) {
            *identity_counts.entry(hit.identity).or_default() += 1;
        }
    }
    let mut result = Vec::new();
    for disk in &disks {
        if index_counts.get(&disk.number).copied() != Some(1) {
            continue;
        }
        let hit = match candidate(disk) {
            Ok(hit) => hit,
            Err(_) => continue,
        };
        if identity_counts.get(&hit.identity).copied() != Some(1) {
            let _reason = Exclusion::IdentityCollision;
            continue;
        }
        let id = opaque_id(&hit.identity, hit.disk.size, salt);
        result.push(Device {
            id,
            model: disk
                .friendly_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("USB storage")
                .to_owned(),
            capacity_bytes: disk.size,
            bus_type: "USB".to_owned(),
            partition_style: disk
                .partition_style
                .clone()
                .unwrap_or_else(|| "Unknown".into()),
            read_only: disk.is_read_only,
        });
    }
    result.sort_by(|a, b| a.model.cmp(&b.model).then(a.id.cmp(&b.id)));
    Ok(result)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_windows_inventory(json: &str) -> Result<Vec<Device>, DiscoveryError> {
    parse_with_salt(json, &PROCESS_SALT)
}

// Fixed read-only Storage commands, never user-controlled PowerShell fragments.
// Guard each USB disk by checking its actual partitions as well as Get-Disk.
// A Get-Partition failure excludes that disk; never assume no protected volumes.
#[cfg(windows)]
const READ_ONLY_WINDOWS_INVENTORY: &str = r#"
$ErrorActionPreference = 'Stop'
$disks = @(Get-Disk -ErrorAction Stop)
$inventory = foreach ($disk in $disks) {
  $partitionKnown = $false
  $protectedPartition = $false
  if ($disk.BusType.ToString() -eq 'USB' -and -not $disk.IsOffline) {
    try {
      $partitions = @($disk | Get-Partition -ErrorAction Stop)
      $partitionKnown = $true
      foreach ($partition in $partitions) {
        if ($partition.IsBoot -or $partition.IsSystem) {
          $protectedPartition = $true
        }
      }
    } catch {
      $partitionKnown = $false
    }
  }
  [pscustomobject]@{
    Number = $disk.Number
    FriendlyName = $disk.FriendlyName
    BusType = $disk.BusType.ToString()
    Size = $disk.Size
    IsBoot = $disk.IsBoot
    IsSystem = $disk.IsSystem
    IsOffline = $disk.IsOffline
    IsReadOnly = $disk.IsReadOnly
    PartitionStyle = $disk.PartitionStyle.ToString()
    UniqueId = $disk.UniqueId
    SerialNumber = $disk.SerialNumber
    Path = $disk.Path
    PartitionSafetyKnown = $partitionKnown
    HasProtectedPartition = $protectedPartition
  }
}
ConvertTo-Json -InputObject @($inventory) -Compress -Depth 4
"#;

#[cfg(windows)]
pub async fn discover() -> Result<Vec<Device>, DiscoveryError> {
    use tokio::{
        process::Command,
        time::{Duration, timeout},
    };
    let output = timeout(
        Duration::from_secs(30),
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                READ_ONLY_WINDOWS_INVENTORY,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| DiscoveryError::Unavailable("disk enumeration timed out".into()))?
    .map_err(|_| DiscoveryError::Unavailable("Windows Storage cmdlets unavailable".into()))?;
    if !output.status.success() {
        return Err(DiscoveryError::Unavailable(
            "Windows Storage inventory failed".into(),
        ));
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err(DiscoveryError::Unavailable(
            "disk inventory response exceeds limit".into(),
        ));
    }
    let json = String::from_utf8(output.stdout)
        .map_err(|_| DiscoveryError::Unavailable("invalid inventory encoding".into()))?;
    parse_windows_inventory(&json)
}

#[cfg(not(windows))]
pub async fn discover() -> Result<Vec<Device>, DiscoveryError> {
    Err(DiscoveryError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(number: u32, path: &str, serial: &str) -> String {
        format!(
            r#"{{"Number":{number},"BusType":"USB","Size":32000000000,"Path":"{path}","SerialNumber":"{serial}","PartitionSafetyKnown":true,"FriendlyName":"USB"}} "#
        )
    }
    const SALT: [u8; 32] = [8; 32];

    #[test]
    fn stable_across_disk_number_reassignment_and_scans() {
        let a = parse_with_salt(&disk(2, "pnp_a", "abc1"), &SALT).unwrap();
        let b = parse_with_salt(&disk(12, "pnp_a", "abc1"), &SALT).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a, b);
        assert!(a[0].id.starts_with("usb-"));
        assert!(!a[0].id.contains("abc1"));
    }
    #[test]
    fn index_reuse_with_new_device_changes_identity() {
        let a = parse_with_salt(&disk(3, "pnp_a", "abc1"), &SALT).unwrap();
        let b = parse_with_salt(&disk(3, "pnp_b", "abc2"), &SALT).unwrap();
        assert_ne!(a[0].id, b[0].id);
    }
    #[test]
    fn process_restart_rotates_opaque_ids() {
        let a = parse_with_salt(&disk(2, "pnp_a", "abc1"), &SALT).unwrap();
        let b = parse_with_salt(&disk(2, "pnp_a", "abc1"), &[9; 32]).unwrap();
        assert_ne!(a[0].id, b[0].id);
    }
    #[test]
    fn invalid_and_ambiguous_identities_are_excluded() {
        let missing = r#"{"Number":1,"BusType":"USB","Size":1000,"PartitionSafetyKnown":true}"#;
        assert!(parse_with_salt(missing, &SALT).unwrap().is_empty());
        let same = format!("[{},{}]", disk(1, "pnp_a", "a"), disk(2, "pnp_a", "a"));
        assert!(parse_with_salt(&same, &SALT).unwrap().is_empty());
        let same_number = format!("[{},{}]", disk(1, "pnp_a", "a"), disk(1, "pnp_b", "b"));
        assert!(parse_with_salt(&same_number, &SALT).unwrap().is_empty());
    }
    #[test]
    fn system_disk_and_protected_partitions_are_not_candidates() {
        let sample = format!(
            r#"[{},
            {{"Number":8,"BusType":"USB","Size":1000,"Path":"pnp_b","SerialNumber":"b","IsBoot":true,"PartitionSafetyKnown":true}},
            {{"Number":9,"BusType":"USB","Size":1000,"Path":"pnp_c","SerialNumber":"c","IsSystem":true,"PartitionSafetyKnown":true}},
            {{"Number":10,"BusType":"USB","Size":1000,"Path":"pnp_d","SerialNumber":"d","HasProtectedPartition":true,"PartitionSafetyKnown":true}},
            {{"Number":11,"BusType":"USB","Size":1000,"Path":"pnp_e","SerialNumber":"e","PartitionSafetyKnown":false}},
            {{"Number":12,"BusType":"NVMe","Size":1000,"Path":"pnp_f","SerialNumber":"f","PartitionSafetyKnown":true}},
            {{"Number":13,"BusType":"USB","Size":0,"Path":"pnp_g","SerialNumber":"g","PartitionSafetyKnown":true}},
            {{"Number":14,"BusType":"USB","Size":1000,"Path":"pnp_h","SerialNumber":"h","IsOffline":true,"PartitionSafetyKnown":true}}]"#,
            disk(2, "pnp_a", "a")
        );
        let only = parse_with_salt(&sample, &SALT).unwrap();
        assert_eq!(only.len(), 1);
    }
    #[test]
    fn write_protected_candidate_is_read_only_in_inventory() {
        let s = r#"{"Number":3,"BusType":"USB","Size":1000,"Path":"pnp_a","UniqueId":"guid","PartitionSafetyKnown":true,"IsReadOnly":true}"#;
        let r = parse_with_salt(s, &SALT).unwrap();
        assert!(r[0].read_only);
    }
    #[test]
    fn malformed_or_large_provider_responses_fail_closed() {
        assert!(parse_with_salt("oops", &SALT).is_err());
        assert!(parse_with_salt(r#"[{"Number":1}]"#, &SALT).is_err());
        assert!(parse_with_salt("123", &SALT).is_err());
        assert!(
            parse_with_salt(
                &format!("[{}]", vec![disk(2, "x", "y"); 513].join(",")),
                &SALT
            )
            .is_err()
        );
        assert!(parse_with_salt("null", &SALT).unwrap().is_empty());
    }
    #[test]
    fn no_write_capability_encoded_in_device_json() {
        let d = parse_with_salt(&disk(1, "pnp_a", "abc"), &SALT).unwrap();
        let serialized = serde_json::to_string(&d).unwrap();
        assert!(!serialized.contains("SerialNumber"));
        assert!(!serialized.contains("pnp_a"));
        assert!(!serialized.contains("PhysicalDrive"));
    }
}
