//! Fail-closed read-only disk/volume protected-role graph.
/// Never decides eligibility, opens device handles, or issues write grants.
use crate::native_ancestry::{NativeObservation, assess_native};
use crate::safety::{Snapshot, assess_snapshots};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskProtection {
    pub disk_number: u32,
    pub is_observed_protected: bool,
    pub shares_volume_with_protected_disk: bool,
    pub ancestry_verified_for_writing: bool,
    pub physical_write_authorized: bool,
    pub risk_codes: Vec<&'static str>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionReport {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub graph_samples_agree: bool,
    pub protected_role_evidence_complete: bool,
    pub disks: Vec<DiskProtection>,
}
/// Both the read-only provider and IOCTL graph must be independently captured
/// twice. This assessment is *not* an authorization or a volume lock.
/// A multi-disk volume transmits OS-protected ancestry to all parents.
pub fn assess_protection(
    first: &Snapshot,
    second: &Snapshot,
    native_first: &NativeObservation,
    native_second: &NativeObservation,
) -> ProtectionReport {
    let disk_set = first
        .disks
        .iter()
        .map(|d| d.number)
        .collect::<BTreeSet<_>>();
    let native = assess_native(&disk_set, native_first, native_second);
    let observed = assess_snapshots(first, second);
    let first_unique = first.disks.len() == disk_set.len();
    let roles_complete = first_unique
        && first.disks.iter().all(|d| {
            d.protected_role_evidence_complete
                && d.partition_evidence_complete
                && d.partitions.iter().all(|p| p.volume_evidence_complete)
        });
    let mut parents = BTreeMap::<u32, BTreeSet<u32>>::new();
    for number in &disk_set {
        parents.insert(*number, BTreeSet::from([*number]));
    }
    let mut mapped = BTreeSet::new();
    let mut unknown_parent = false;
    for volume in &native_first.volumes {
        let peers = volume
            .extents
            .iter()
            .map(|e| e.disk_number)
            .collect::<BTreeSet<_>>();
        for disk in &peers {
            mapped.insert(*disk);
            if !disk_set.contains(disk) {
                unknown_parent = true;
            }
        }
        for disk in &peers {
            parents
                .entry(*disk)
                .or_default()
                .extend(peers.iter().copied());
        }
    }
    // A whole-disk OS boot/system flag or any partition role is protected.
    // We never rely on a drive letter alone, because mounted volumes may be
    // relocated, shadowed, or span multiple disks.
    let roots = first
        .disks
        .iter()
        .filter(|d| {
            d.is_boot
                || d.is_system
                || d.partitions
                    .iter()
                    .any(|p| p.is_boot || p.is_system || p.has_protected_role)
        })
        .map(|d| d.number)
        .collect::<BTreeSet<_>>();
    let mut protected = roots.clone();
    // Bounded fixed-point propagation through volume-sharing graph.
    for _ in 0..(disk_set.len() + 1) {
        let prior = protected.len();
        let additional = protected
            .iter()
            .filter_map(|d| parents.get(d))
            .flat_map(|set| set.iter().copied())
            .collect::<BTreeSet<_>>();
        protected.extend(additional);
        if protected.len() == prior {
            break;
        }
    }
    let stable = first == second
        && native_first == native_second
        && observed
            .findings
            .iter()
            .all(|f| f.identity_stable_between_samples);
    let mut disks = vec![];
    for disk in &first.disks {
        let mut risk_codes = vec![];
        if roots.contains(&disk.number) {
            risk_codes.push("protected_os_disk_or_partition");
        }
        if protected.contains(&disk.number) && !roots.contains(&disk.number) {
            risk_codes.push("shared_volume_with_protected_parent");
        }
        if !mapped.contains(&disk.number) {
            risk_codes.push("volume_ancestry_unmapped");
        }
        if unknown_parent {
            risk_codes.push("volume_ancestry_foreign_parent");
        }
        if !native.native_ancestry_complete {
            risk_codes.push("native_extent_evidence_incomplete");
        }
        if !roles_complete {
            risk_codes.push("protected_roles_unverified");
        }
        if !stable {
            risk_codes.push("observations_changed_or_incomplete");
        }
        if disk.bus_type != "USB" {
            risk_codes.push("bus_not_usb");
        }
        if disk.is_read_only {
            risk_codes.push("disk_read_only");
        }
        if disk.is_offline {
            risk_codes.push("disk_offline");
        }
        risk_codes.sort_unstable();
        risk_codes.dedup();
        disks.push(DiskProtection {
            disk_number: disk.number,
            is_observed_protected: roots.contains(&disk.number),
            shares_volume_with_protected_disk: protected.contains(&disk.number)
                && !roots.contains(&disk.number),
            ancestry_verified_for_writing: false,
            physical_write_authorized: false,
            risk_codes,
        });
    }
    disks.sort_by_key(|d| d.disk_number);
    ProtectionReport {
        read_only: true,
        physical_write_authorized: false,
        graph_samples_agree: stable && native.two_snapshots_agree,
        protected_role_evidence_complete: roles_complete,
        disks,
    }
}
