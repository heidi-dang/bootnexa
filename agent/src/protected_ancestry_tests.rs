use crate::{
    native_ancestry::{NativeExtent, NativeObservation, NativeVolume},
    protected_ancestry::assess_protection,
    safety::{DiskEvidence, PartitionEvidence, Snapshot},
};
fn disk(number: u32, boot: bool) -> DiskEvidence {
    DiskEvidence {
        number,
        bus_type: "USB".into(),
        capacity_bytes: 32 * 1024 * 1024,
        pnp_instance_id: Some(format!("PNP-{number}")),
        win32_device_id: Some(format!("DRIVE-{number}")),
        path: Some(format!("DEV-{number}")),
        serial_number: Some(format!("SERIAL-{number}")),
        unique_id: Some(format!("UID-{number}")),
        is_boot: boot,
        is_system: false,
        is_offline: false,
        is_read_only: false,
        partition_evidence_complete: true,
        protected_role_evidence_complete: false,
        volume_extents_complete: false,
        partitions: vec![PartitionEvidence {
            number: 1,
            is_boot: false,
            is_system: false,
            is_active: false,
            has_protected_role: false,
            volume_evidence_complete: true,
            drive_letter: Some("E".into()),
            volume_unique_id: Some(format!("VOLUME-{number}")),
            access_paths: vec![],
        }],
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        schema_version: 1,
        disks: vec![disk(0, true), disk(1, false), disk(2, false)],
    }
}
fn extent(disk_number: u32) -> NativeExtent {
    NativeExtent {
        disk_number,
        starting_offset: 1048576,
        extent_bytes: 2048,
    }
}
fn native() -> NativeObservation {
    NativeObservation {
        disk_interface_numbers: vec![0, 1, 2],
        volumes: vec![
            NativeVolume {
                extents: vec![extent(0), extent(1)],
            },
            NativeVolume {
                extents: vec![extent(2)],
            },
        ],
        interfaces_complete: true,
        volumes_complete: true,
    }
}
#[test]
fn protected_os_volume_propagates_to_all_extent_parents() {
    let s = snapshot();
    let n = native();
    let result = assess_protection(&s, &s, &n, &n);
    assert!(result.read_only);
    assert!(!result.physical_write_authorized);
    assert!(!result.protected_role_evidence_complete);
    assert!(result.disks[0].is_observed_protected);
    assert!(result.disks[1].shares_volume_with_protected_disk);
    assert!(
        result.disks[1]
            .risk_codes
            .contains(&"shared_volume_with_protected_parent")
    );
    assert!(!result.disks[2].shares_volume_with_protected_disk);
    assert!(
        result
            .disks
            .iter()
            .all(|d| !d.ancestry_verified_for_writing && !d.physical_write_authorized)
    );
}
#[test]
fn disconnected_volume_links_and_unknown_parents_fail_closed() {
    let s = snapshot();
    let mut n = native();
    n.volumes[0].extents.push(extent(20));
    let result = assess_protection(&s, &s, &n, &n);
    assert!(
        result
            .disks
            .iter()
            .all(|d| d.risk_codes.contains(&"volume_ancestry_foreign_parent"))
    );
    assert!(!result.physical_write_authorized);
    n.volumes
        .retain(|v| v.extents.iter().any(|e| e.disk_number == 0));
    let result = assess_protection(&s, &s, &n, &n);
    assert!(
        result.disks[2]
            .risk_codes
            .contains(&"volume_ancestry_unmapped")
    );
}
#[test]
fn role_on_partition_instead_of_disk_is_still_protected() {
    let mut s = snapshot();
    s.disks[0].is_boot = false;
    s.disks[1].partitions[0].has_protected_role = true;
    let n = native();
    let result = assess_protection(&s, &s, &n, &n);
    assert!(result.disks[0].shares_volume_with_protected_disk);
    assert!(result.disks[1].is_observed_protected);
}
#[test]
fn drift_and_missing_role_evidence_never_yield_safe_ancestry() {
    let s = snapshot();
    let mut t = s.clone();
    t.disks[1].capacity_bytes += 1;
    let n = native();
    let result = assess_protection(&s, &t, &n, &n);
    assert!(!result.graph_samples_agree);
    assert!(
        result
            .disks
            .iter()
            .all(|d| d.risk_codes.contains(&"observations_changed_or_incomplete"))
    );
    let mut m = n.clone();
    m.volumes_complete = false;
    let result = assess_protection(&s, &s, &n, &m);
    assert!(!result.graph_samples_agree);
    assert!(!result.physical_write_authorized);
}
#[test]
fn no_known_protected_root_is_not_authorization() {
    let mut s = snapshot();
    s.disks[0].is_boot = false;
    let n = native();
    let result = assess_protection(&s, &s, &n, &n);
    assert!(!result.protected_role_evidence_complete);
    assert!(
        result
            .disks
            .iter()
            .all(|d| d.risk_codes.contains(&"protected_roles_unverified"))
    );
    assert!(result.disks.iter().all(|d| !d.physical_write_authorized));
}
