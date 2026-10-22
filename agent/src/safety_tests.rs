use crate::safety::{
    DiskEvidence, PartitionEvidence, SafetyError, Snapshot, assess_snapshots, parse_snapshot,
};
fn disk(index: u32) -> DiskEvidence {
    DiskEvidence {
        number: index,
        bus_type: "USB".into(),
        capacity_bytes: 32_000_000_000,
        pnp_instance_id: Some(format!("USBSTOR\\disk&ven_qa\\serial_{index}")),
        win32_device_id: Some(format!(r"\\.\PHYSICALDRIVE{index}")),
        path: Some(format!("SCSI\\Disk&ven_QA&device_{index}")),
        serial_number: Some(format!("SERIAL-{index}")),
        unique_id: Some(format!("GUID-{index}")),
        is_boot: false,
        is_system: false,
        is_offline: false,
        is_read_only: false,
        partition_evidence_complete: true,
        protected_role_evidence_complete: true,
        volume_extents_complete: false,
        partitions: vec![PartitionEvidence {
            number: 1,
            is_boot: false,
            is_system: false,
            is_active: false,
            has_protected_role: false,
            volume_evidence_complete: true,
            drive_letter: Some("E".into()),
            volume_unique_id: Some(format!("volume-{index}")),
            access_paths: vec!["E:\\".into()],
        }],
    }
}
fn snapshots() -> (Snapshot, Snapshot) {
    let s = Snapshot {
        schema_version: 1,
        disks: vec![disk(3)],
    };
    (s.clone(), s)
}
fn report(a: &Snapshot, b: &Snapshot) -> Vec<&'static str> {
    let r = assess_snapshots(a, b);
    assert!(r.read_only);
    assert!(!r.physical_write_authorized);
    assert_eq!(r.snapshot_count, 2);
    assert!(r.findings.iter().all(|f| !f.physical_write_authorized));
    r.findings[0].risk_codes.clone()
}
#[test]
fn consistent_independent_snapshots_are_read_only_observations_not_write_grants() {
    let (before, after) = snapshots();
    let r = assess_snapshots(&before, &after);
    assert!(r.findings[0].identity_stable_between_samples);
    assert_eq!(
        r.findings[0].risk_codes,
        vec!["native_volume_extents_unverified"]
    );
    assert!(r.findings[0].diagnostic_tag.starts_with("diag-"));
    assert!(!r.physical_write_authorized);
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("SERIAL-3"));
    assert!(!json.contains("PHYSICALDRIVE3"));
    assert!(!json.contains("USBSTOR"));
}
#[test]
fn every_mutated_property_or_protected_role_invalidates_safety_observation() {
    let (baseline, mut copy) = snapshots();
    copy.disks[0].capacity_bytes = 64_000_000_000;
    assert!(report(&baseline, &copy).contains(&"identity_or_topology_changed"));
    let (baseline, mut copy) = snapshots();
    copy.disks[0].pnp_instance_id = Some("swapped-usb-device".into());
    assert!(report(&baseline, &copy).contains(&"identity_or_topology_changed"));
    let (baseline, mut copy) = snapshots();
    copy.disks[0].number = 9;
    assert!(report(&baseline, &copy).contains(&"identity_or_topology_changed"));
    let (baseline, mut copy) = snapshots();
    copy.disks[0].partitions[0].volume_unique_id = Some("volume-swapped".into());
    assert!(report(&baseline, &copy).contains(&"identity_or_topology_changed"));
    let (baseline, mut copy) = snapshots();
    copy.disks[0].partitions[0].access_paths.push("F:\\".into());
    assert!(report(&baseline, &copy).contains(&"identity_or_topology_changed"));
    let (baseline, mut copy) = snapshots();
    copy.disks.push(disk(4));
    assert!(report(&baseline, &copy).contains(&"inventory_changed"));
}
#[test]
fn all_fail_closed_classifications_produce_specific_reasons() {
    let baseline = disk(3);
    let mut variants = Vec::<(DiskEvidence, &str)>::new();
    let mut d = baseline.clone();
    d.bus_type = "NVMe".into();
    variants.push((d, "bus_not_usb"));
    let mut d = baseline.clone();
    d.capacity_bytes = 0;
    variants.push((d, "size_unknown"));
    let mut d = baseline.clone();
    d.is_boot = true;
    variants.push((d, "os_boot_or_system_disk"));
    let mut d = baseline.clone();
    d.is_system = true;
    variants.push((d, "os_boot_or_system_disk"));
    let mut d = baseline.clone();
    d.is_offline = true;
    variants.push((d, "disk_offline"));
    let mut d = baseline.clone();
    d.is_read_only = true;
    variants.push((d, "disk_read_only"));
    let mut d = baseline.clone();
    d.partition_evidence_complete = false;
    variants.push((d, "partition_or_role_evidence_incomplete"));
    let mut d = baseline.clone();
    d.protected_role_evidence_complete = false;
    variants.push((d, "partition_or_role_evidence_incomplete"));
    let mut d = baseline.clone();
    d.partitions[0].volume_evidence_complete = false;
    variants.push((d, "partition_or_role_evidence_incomplete"));
    let mut d = baseline.clone();
    d.partitions[0].is_boot = true;
    variants.push((d, "protected_partition_or_volume"));
    let mut d = baseline.clone();
    d.partitions[0].is_system = true;
    variants.push((d, "protected_partition_or_volume"));
    let mut d = baseline.clone();
    d.partitions[0].has_protected_role = true;
    variants.push((d, "protected_partition_or_volume"));
    let mut d = baseline.clone();
    d.partitions.push(d.partitions[0].clone());
    variants.push((d, "partition_or_role_evidence_incomplete"));
    let mut d = baseline.clone();
    d.pnp_instance_id = None;
    variants.push((d, "identity_unknown"));
    let mut d = baseline.clone();
    d.serial_number = None;
    d.unique_id = None;
    variants.push((d, "identity_unknown"));
    let mut d = baseline.clone();
    d.serial_number = Some("To be filled by O.E.M.".into());
    d.unique_id = None;
    variants.push((d, "identity_unknown"));
    for (bad, reason) in variants {
        let snap = Snapshot {
            schema_version: 1,
            disks: vec![bad],
        };
        let codes = report(&snap, &snap);
        assert!(
            codes.contains(&reason),
            "missing {reason}; returned {codes:?}"
        );
    }
}
#[test]
fn duplicated_disk_indices_and_physical_fingerprints_are_not_accepted() {
    let mut both = Snapshot {
        schema_version: 1,
        disks: vec![disk(3), disk(4)],
    };
    both.disks[1].number = 3;
    for finding in assess_snapshots(&both, &both).findings {
        assert!(
            finding
                .risk_codes
                .contains(&"duplicate_or_reused_disk_number")
        );
        assert!(!finding.identity_stable_between_samples);
    }
    let mut both = Snapshot {
        schema_version: 1,
        disks: vec![disk(3), disk(4)],
    };
    both.disks[1].pnp_instance_id = both.disks[0].pnp_instance_id.clone();
    // Future helper must not treat copied PnP identifiers as unique even if
    // different paths or serials change the composite hash.
    assert!(
        assess_snapshots(&both, &both)
            .findings
            .iter()
            .all(|f| f.risk_codes.contains(&"duplicate_pnp_instance_id"))
    );
    let mut both = Snapshot {
        schema_version: 1,
        disks: vec![disk(3), disk(4)],
    };
    both.disks[1] = both.disks[0].clone();
    both.disks[1].number = 4;
    assert!(
        assess_snapshots(&both, &both)
            .findings
            .iter()
            .all(|f| f.risk_codes.contains(&"duplicate_physical_identity"))
    );
}
#[test]
fn strict_schema_bounds_and_unknown_fields_fail_closed() {
    let (sample, _) = snapshots();
    let raw = serde_json::to_string(&sample).unwrap();
    assert_eq!(parse_snapshot(&raw).unwrap(), sample);
    let malformed = [
        "{}",
        "[]",
        "null",
        "invalid",
        "{\"SchemaVersion\":1}",
        "{\"SchemaVersion\":0,\"Disks\":[]}",
        "{\"SchemaVersion\":2,\"Disks\":[]}",
        "{\"SchemaVersion\":1,\"Disks\":[],\"WriteEnabled\":true}",
    ];
    for (i, raw) in malformed.iter().enumerate() {
        assert!(
            parse_snapshot(raw).is_err(),
            "accepted malformed fixture {i}"
        );
    }
    let mut over = sample.clone();
    over.disks[0].path = Some("A".repeat(2049));
    assert!(matches!(
        parse_snapshot(&serde_json::to_string(&over).unwrap()),
        Err(SafetyError::InvalidSnapshot)
    ));
    let many = Snapshot {
        schema_version: 1,
        disks: (0..129).map(disk).collect(),
    };
    assert!(parse_snapshot(&serde_json::to_string(&many).unwrap()).is_err());
    assert!(parse_snapshot(&"x".repeat(1024 * 1024 + 1)).is_err());
}
#[test]
fn empty_inventory_is_safe_to_inspect_but_never_authorizes() {
    let empty = Snapshot {
        schema_version: 1,
        disks: vec![],
    };
    let report = assess_snapshots(&empty, &empty);
    assert!(report.findings.is_empty());
    assert!(!report.physical_write_authorized);
}
