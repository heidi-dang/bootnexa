//! Independent read-only safety probe contract (NOT a privileged writer).
//! No disk handles, commands accepting device indices, elevation or approval API.
//! Validation reports uncertainties; nothing in this module grants write authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_DISKS: usize = 128;
const MAX_PARTITIONS: usize = 128;
const MAX_FIELD: usize = 2048;

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("invalid Windows read-only snapshot")]
    InvalidSnapshot,
    #[error("snapshot schema is unsupported")]
    UnsupportedSchema,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u32,
    pub disks: Vec<DiskEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct DiskEvidence {
    pub number: u32,
    pub bus_type: String,
    pub capacity_bytes: u64,
    pub pnp_instance_id: Option<String>,
    pub win32_device_id: Option<String>,
    pub path: Option<String>,
    pub serial_number: Option<String>,
    pub unique_id: Option<String>,
    pub is_boot: bool,
    pub is_system: bool,
    pub is_offline: bool,
    pub is_read_only: bool,
    pub partition_evidence_complete: bool,
    pub protected_role_evidence_complete: bool,
    pub volume_extents_complete: bool,
    pub partitions: Vec<PartitionEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct PartitionEvidence {
    pub number: u32,
    pub is_boot: bool,
    pub is_system: bool,
    pub is_active: bool,
    pub has_protected_role: bool,
    pub volume_evidence_complete: bool,
    pub drive_letter: Option<String>,
    pub volume_unique_id: Option<String>,
    pub access_paths: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyFinding {
    pub disk_number: u32,
    /// Only a diagnostic pseudonym, never an authorization capability.
    pub diagnostic_tag: String,
    pub identity_stable_between_samples: bool,
    pub physical_write_authorized: bool,
    pub risk_codes: Vec<&'static str>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyReport {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub snapshot_count: u8,
    pub findings: Vec<SafetyFinding>,
}
pub fn parse_snapshot(value: &str) -> Result<Snapshot, SafetyError> {
    if value.len() > MAX_SNAPSHOT_BYTES {
        return Err(SafetyError::InvalidSnapshot);
    }
    let snapshot: Snapshot =
        serde_json::from_str(value).map_err(|_| SafetyError::InvalidSnapshot)?;
    if snapshot.schema_version != 1 {
        return Err(SafetyError::UnsupportedSchema);
    }
    if snapshot.disks.len() > MAX_DISKS {
        return Err(SafetyError::InvalidSnapshot);
    }
    for disk in &snapshot.disks {
        if disk.partitions.len() > MAX_PARTITIONS
            || !bounded(&disk.bus_type)
            || !optional_bounded(&disk.pnp_instance_id)
            || !optional_bounded(&disk.win32_device_id)
            || !optional_bounded(&disk.path)
            || !optional_bounded(&disk.serial_number)
            || !optional_bounded(&disk.unique_id)
        {
            return Err(SafetyError::InvalidSnapshot);
        }
        for partition in &disk.partitions {
            if !optional_bounded(&partition.drive_letter)
                || !optional_bounded(&partition.volume_unique_id)
                || partition.access_paths.len() > 64
                || partition.access_paths.iter().any(|x| !bounded(x))
            {
                return Err(SafetyError::InvalidSnapshot);
            }
        }
    }
    Ok(snapshot)
}
fn bounded(x: &str) -> bool {
    x.len() <= MAX_FIELD && !x.contains('\0')
}
fn optional_bounded(x: &Option<String>) -> bool {
    x.as_deref().is_none_or(bounded)
}
fn normalized(x: Option<&str>) -> Option<String> {
    let x = x?.trim().to_ascii_lowercase();
    if x.is_empty()
        || x.len() > MAX_FIELD
        || matches!(
            x.as_str(),
            "0" | "null" | "unknown" | "none" | "n/a" | "to be filled by o.e.m."
        )
    {
        return None;
    }
    Some(x)
}
fn identities(disk: &DiskEvidence) -> Option<String> {
    let pnp = normalized(disk.pnp_instance_id.as_deref())?;
    let path = normalized(disk.path.as_deref())?;
    let native = normalized(disk.win32_device_id.as_deref())?;
    let serial = normalized(disk.serial_number.as_deref());
    let unique = normalized(disk.unique_id.as_deref());
    if serial.is_none() && unique.is_none() {
        return None;
    }
    // Delimit with lengths: neither provider strings nor disk number can alias.
    Some(
        [
            pnp,
            path,
            native,
            serial.unwrap_or_default(),
            unique.unwrap_or_default(),
        ]
        .iter()
        .map(|s| format!("{}:{s}", s.len()))
        .collect::<Vec<_>>()
        .join("|"),
    )
}
fn coherent_layout(disk: &DiskEvidence) -> bool {
    if !disk.partition_evidence_complete || !disk.protected_role_evidence_complete {
        return false;
    }
    let mut seen = HashSet::new();
    disk.partitions.iter().all(|p| seen.insert(p.number))
        && disk.partitions.iter().all(|p| p.volume_evidence_complete)
}
/// Compare two independently retrieved snapshots; the second observation is
/// not a lock or Windows device-generation claim and grants ZERO authority.
pub fn assess_snapshots(first: &Snapshot, second: &Snapshot) -> SafetyReport {
    let mut numbers = HashMap::<u32, usize>::new();
    let mut identity_counts = HashMap::<String, usize>::new();
    let mut next_numbers = HashMap::<u32, usize>::new();
    let mut next_identities = HashMap::<String, usize>::new();
    let mut pnp_counts = HashMap::<String, usize>::new();
    let mut next_pnp_counts = HashMap::<String, usize>::new();
    for d in &first.disks {
        *numbers.entry(d.number).or_default() += 1;
        if let Some(pnp) = normalized(d.pnp_instance_id.as_deref()) {
            *pnp_counts.entry(pnp).or_default() += 1;
        }
        if let Some(id) = identities(d) {
            *identity_counts.entry(id).or_default() += 1;
        }
    }
    for d in &second.disks {
        *next_numbers.entry(d.number).or_default() += 1;
        if let Some(pnp) = normalized(d.pnp_instance_id.as_deref()) {
            *next_pnp_counts.entry(pnp).or_default() += 1;
        }
        if let Some(id) = identities(d) {
            *next_identities.entry(id).or_default() += 1;
        }
    }
    let mut findings = Vec::with_capacity(first.disks.len());
    for disk in &first.disks {
        let id = identities(disk);
        let mut risk_codes = Vec::new();
        if disk.bus_type != "USB" {
            risk_codes.push("bus_not_usb");
        }
        if disk.capacity_bytes == 0 {
            risk_codes.push("size_unknown");
        }
        if disk.is_boot || disk.is_system {
            risk_codes.push("os_boot_or_system_disk");
        }
        if disk.is_offline {
            risk_codes.push("disk_offline");
        }
        if disk.is_read_only {
            risk_codes.push("disk_read_only");
        }
        if !coherent_layout(disk) {
            risk_codes.push("partition_or_role_evidence_incomplete");
        }
        if disk
            .partitions
            .iter()
            .any(|p| p.is_boot || p.is_system || p.has_protected_role)
        {
            risk_codes.push("protected_partition_or_volume");
        }
        // Cmdlets cannot attest all multi-disk volume extents. Native IOCTL
        // verification is a hard requirement for a future privileged writer.
        if !disk.volume_extents_complete {
            risk_codes.push("native_volume_extents_unverified");
        }
        if id.is_none() {
            risk_codes.push("identity_unknown");
        }
        if let Some(pnp) = normalized(disk.pnp_instance_id.as_deref())
            && (pnp_counts.get(&pnp) != Some(&1) || next_pnp_counts.get(&pnp) != Some(&1))
        {
            risk_codes.push("duplicate_pnp_instance_id");
        }
        if numbers.get(&disk.number) != Some(&1) || next_numbers.get(&disk.number) != Some(&1) {
            risk_codes.push("duplicate_or_reused_disk_number");
        }
        if let Some(id) = &id
            && (identity_counts.get(id) != Some(&1) || next_identities.get(id) != Some(&1))
        {
            risk_codes.push("duplicate_physical_identity");
        }
        // Even a stable identity is an observation only: a hot-swap can occur
        // after this check. Future helper must guard the opened handle.
        let matched = second
            .disks
            .iter()
            .filter(|d| d.number == disk.number)
            .collect::<Vec<_>>();
        let stable = matched.len() == 1 && {
            let current = matched[0];
            id.is_some()
                && id == identities(current)
                && *disk == *current
                && disk.partition_evidence_complete
                && disk
                    .partitions
                    .iter()
                    .map(|p| p.number)
                    .collect::<HashSet<_>>()
                    .len()
                    == disk.partitions.len()
                && numbers.get(&disk.number) == Some(&1)
                && next_numbers.get(&disk.number) == Some(&1)
                && identity_counts.get(id.as_ref().unwrap()) == Some(&1)
                && next_identities.get(id.as_ref().unwrap()) == Some(&1)
                && normalized(disk.pnp_instance_id.as_deref()).is_some_and(|pnp| {
                    pnp_counts.get(&pnp) == Some(&1) && next_pnp_counts.get(&pnp) == Some(&1)
                })
        };
        if !stable {
            risk_codes.push("identity_or_topology_changed");
        }
        // New random salt per report prevents correlating local storage
        // identifiers between diagnostic executions or dictionary guessing.
        let diagnostic_salt: [u8; 32] = rand::random();
        let mut hasher = Sha256::new();
        hasher.update(diagnostic_salt);
        hasher.update(id.as_deref().unwrap_or("unknown").as_bytes());
        let digest = hasher.finalize();
        findings.push(SafetyFinding {
            disk_number: disk.number,
            diagnostic_tag: format!("diag-{}", hex::encode(&digest[..6])),
            identity_stable_between_samples: stable,
            physical_write_authorized: false,
            risk_codes,
        });
    }
    // An unexpected new disk is a snapshot change, never a write permission.
    if first.disks.len() != second.disks.len() {
        for finding in &mut findings {
            finding.identity_stable_between_samples = false;
            if !finding.risk_codes.contains(&"inventory_changed") {
                finding.risk_codes.push("inventory_changed");
            }
        }
    }
    findings.sort_by_key(|f| f.disk_number);
    SafetyReport {
        read_only: true,
        physical_write_authorized: false,
        snapshot_count: 2,
        findings,
    }
}

#[cfg(windows)]
const READ_ONLY_PROBE: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
# Fixed provider commands. No external user data is ever interpolated.
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$pagefiles = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop)
$systemDrive = $os.SystemDrive.TrimEnd('\').ToUpperInvariant()
$protectedDrives = @($systemDrive)
foreach ($page in $pagefiles) {
  if ($page.Name -match '^[A-Za-z]:') { $protectedDrives += $page.Name.Substring(0,2).ToUpperInvariant() }
}
$diskList = @(Get-Disk -ErrorAction Stop)
$cimDisks = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop)
$records = foreach ($disk in $diskList) {
  $number = [int]$disk.Number
  $nativeDiskRows = @($cimDisks | Where-Object { $_.Index -eq $number })
  $native = if ($nativeDiskRows.Count -eq 1) { $nativeDiskRows[0] } else { $null }
  $complete = $false
  $partitions = @()
  try {
    $partitionRows = @($disk | Get-Partition -ErrorAction Stop)
    $complete = $true
    foreach ($p in $partitionRows) {
      $paths = @($p.AccessPaths | Where-Object { $_ -is [string] -and $_.Length -gt 0 })
      $letter = if ($p.DriveLetter) { [string]$p.DriveLetter } else { $null }
      $protected = [bool]($p.IsBoot -or $p.IsSystem)
      if ($letter -and ($protectedDrives -contains ($letter + ':').ToUpperInvariant())) { $protected = $true }
      $volumeEvidence = $false
      $volumeId = $null
      try {
        $volumes = @($p | Get-Volume -ErrorAction Stop)
        if ($volumes.Count -eq 1) {
          $volumeId = [string]$volumes[0].UniqueId
          $volumeEvidence = [bool]($volumeId -and $volumeId.Trim())
        }
      } catch {
        $volumeEvidence = $false
      }
      $partitions += [pscustomobject]@{
        Number = [int]$p.PartitionNumber
        IsBoot = [bool]$p.IsBoot
        IsSystem = [bool]$p.IsSystem
        IsActive = [bool]$p.IsActive
        HasProtectedRole = [bool]$protected
        VolumeEvidenceComplete = [bool]$volumeEvidence
        DriveLetter = $letter
        VolumeUniqueId = $volumeId
        AccessPaths = @($paths)
      }
    }
  } catch { $complete = $false; $partitions = @() }
  [pscustomobject]@{
    Number = $number
    BusType = $disk.BusType.ToString()
    CapacityBytes = [uint64]$disk.Size
    PnpInstanceId = if ($native) { [string]$native.PNPDeviceID } else { $null }
    Win32DeviceId = if ($native) { [string]$native.DeviceID } else { $null }
    Path = [string]$disk.Path
    SerialNumber = [string]$disk.SerialNumber
    UniqueId = [string]$disk.UniqueId
    IsBoot = [bool]$disk.IsBoot
    IsSystem = [bool]$disk.IsSystem
    IsOffline = [bool]$disk.IsOffline
    IsReadOnly = [bool]$disk.IsReadOnly
    PartitionEvidenceComplete = [bool]$complete
    ProtectedRoleEvidenceComplete = $false # Crashdump/hibernation roles not fully attested.
    VolumeExtentsComplete = $false # Requires native IOCTL mapping in future broker.
    Partitions = @($partitions)
  }
}
ConvertTo-Json -InputObject ([pscustomobject]@{ SchemaVersion=1; Disks=@($records) }) -Compress -Depth 8
"#;

#[cfg(windows)]
pub async fn capture_windows() -> Result<Snapshot, SafetyError> {
    use tokio::{
        process::Command,
        time::{Duration, timeout},
    };
    let output = timeout(
        Duration::from_secs(30),
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", READ_ONLY_PROBE])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| SafetyError::InvalidSnapshot)?
    .map_err(|_| SafetyError::InvalidSnapshot)?;
    if !output.status.success() || output.stdout.len() > MAX_SNAPSHOT_BYTES {
        return Err(SafetyError::InvalidSnapshot);
    }
    let json = String::from_utf8(output.stdout).map_err(|_| SafetyError::InvalidSnapshot)?;
    parse_snapshot(json.trim_start_matches('\u{feff}'))
}
