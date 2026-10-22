use crate::native_ancestry::{NativeExtent, NativeObservation, NativeVolume, assess_native};
use std::collections::BTreeSet;
fn observation() -> NativeObservation {
    NativeObservation {
        disk_interface_numbers: vec![1],
        volumes: vec![NativeVolume {
            extents: vec![NativeExtent {
                disk_number: 1,
                starting_offset: 1048576,
                extent_bytes: 16 * 1048576,
            }],
        }],
        interfaces_complete: true,
        volumes_complete: true,
    }
}
fn report(snapshot: &NativeObservation) -> crate::native_ancestry::NativeAncestryReport {
    assess_native(&BTreeSet::from([1]), snapshot, snapshot)
}
#[test]
fn complete_read_only_extent_snapshot_never_grants_physical_writing() {
    let data = observation();
    let result = report(&data);
    assert!(result.two_snapshots_agree);
    assert!(result.native_ancestry_complete);
    assert!(result.risk_codes.is_empty());
    assert_eq!(result.mapped_extents, 1);
    assert_eq!(result.disk_interfaces, 1);
    assert_eq!(result.scanned_volumes, 1);
    assert!(result.read_only);
    assert!(!result.physical_write_authorized);
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"physicalWriteAuthorized\":false"));
    assert!(!json.contains("\\\\?\\\\Volume"));
}
#[test]
fn native_interface_duplicates_and_missing_parent_disks_are_blocked() {
    let mut data = observation();
    data.disk_interface_numbers.push(1);
    assert!(
        report(&data)
            .risk_codes
            .contains(&"duplicate_disk_interface")
    );
    let mut data = observation();
    data.disk_interface_numbers = vec![2];
    let result = report(&data);
    assert!(result.risk_codes.contains(&"unknown_interface_disk"));
    assert!(result.risk_codes.contains(&"disk_interface_missing"));
    assert!(result.risk_codes.contains(&"unknown_volume_parent_disk"));
    assert!(!result.native_ancestry_complete);
    let mut data = observation();
    data.volumes[0].extents[0].disk_number = 2;
    assert!(
        report(&data)
            .risk_codes
            .contains(&"unknown_volume_parent_disk")
    );
}
#[test]
fn multi_disk_extents_are_identified_and_never_authorized() {
    let mut data = observation();
    data.disk_interface_numbers.push(2);
    data.volumes[0].extents.push(NativeExtent {
        disk_number: 2,
        starting_offset: 0,
        extent_bytes: 4 * 1024 * 1024,
    });
    let result = assess_native(&BTreeSet::from([1, 2]), &data, &data);
    assert!(
        result
            .risk_codes
            .contains(&"multi_disk_volume_needs_protected_role_mapping")
    );
    assert_eq!(result.mapped_extents, 2);
    assert!(!result.native_ancestry_complete);
    assert!(!result.physical_write_authorized);
}
#[test]
fn incomplete_native_queries_and_invalid_extent_ranges_fail_closed() {
    for edit in 0..6 {
        let mut data = observation();
        match edit {
            0 => data.interfaces_complete = false,
            1 => data.volumes_complete = false,
            2 => data.volumes[0].extents.clear(),
            3 => data.volumes[0].extents[0].extent_bytes = 0,
            4 => data.volumes[0].extents[0].starting_offset = u64::MAX,
            5 => data.volumes.clear(),
            _ => unreachable!(),
        }
        let result = report(&data);
        assert!(
            !result.native_ancestry_complete,
            "case {edit} unexpectedly passed"
        );
        assert!(!result.risk_codes.is_empty());
    }
}
#[test]
fn native_observations_are_invalidated_by_any_topology_mutation() {
    let first = observation();
    for edit in 0..5 {
        let mut second = first.clone();
        match edit {
            0 => second.volumes[0].extents[0].extent_bytes += 1,
            1 => second.volumes[0].extents[0].starting_offset += 1,
            2 => second.disk_interface_numbers = vec![2],
            3 => second.volumes.push(second.volumes[0].clone()),
            4 => second.volumes_complete = false,
            _ => unreachable!(),
        }
        let result = assess_native(&BTreeSet::from([1]), &first, &second);
        assert!(!result.two_snapshots_agree);
        assert!(result.risk_codes.contains(&"native_topology_changed"));
        assert!(!result.physical_write_authorized);
    }
}
#[test]
fn native_snapshot_serializes_without_win32_paths_or_device_handles() {
    let data = observation();
    let roundtrip: NativeObservation =
        serde_json::from_str(&serde_json::to_string(&data).unwrap()).unwrap();
    assert_eq!(data, roundtrip);
    assert!(std::mem::size_of::<NativeExtent>() <= 24);
}
