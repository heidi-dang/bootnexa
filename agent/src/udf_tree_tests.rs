use super::*;
#[test]
fn compressed_udf_names_are_ascii_only_and_case_normalized() {
    assert_eq!(filename(b"\x08boot.wim").unwrap(), "BOOT.WIM");
    assert_eq!(filename(b"\x10\0b\0o\0o\0t").unwrap(), "BOOT");
    for bad in [
        &b"\x08../BOOT"[..],
        &b"\x08c:\\evil"[..],
        &b"\x08file."[..],
        &b"\x08\xff"[..],
        &b"\x10\0b\0o\0"[..],
    ] {
        assert!(filename(bad).is_err(), "unsafe UDF name accepted: {bad:?}");
    }
}
fn fid(block: u32, part: u16, location: u32) -> Vec<u8> {
    let id = b"\x08BOOT.WIM";
    let unpadded = 38 + id.len();
    let padded = (unpadded + 3) & !3;
    let mut b = vec![0; padded];
    b[0..2].copy_from_slice(&257u16.to_le_bytes());
    b[2..4].copy_from_slice(&2u16.to_le_bytes());
    b[10..12].copy_from_slice(&((unpadded - 16) as u16).to_le_bytes());
    b[12..16].copy_from_slice(&location.to_le_bytes());
    b[16..18].copy_from_slice(&1u16.to_le_bytes());
    b[19] = id.len() as u8;
    b[20..24].copy_from_slice(&2048u32.to_le_bytes());
    b[24..28].copy_from_slice(&block.to_le_bytes());
    b[28..30].copy_from_slice(&part.to_le_bytes());
    b[38..38 + id.len()].copy_from_slice(id);
    let crc = crc16(&b[16..unpadded]);
    b[8..10].copy_from_slice(&crc.to_le_bytes());
    b[4] = b[..16]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .fold(0u8, |sum, (_, v)| sum.wrapping_add(*v));
    b
}
#[test]
fn fid_requires_correct_crc_partition_logical_location_and_full_record() {
    let valid = fid(5, 7, 3);
    assert_eq!(
        checked_fid(&valid, 0, 3, 7).unwrap().1.unwrap(),
        ("BOOT.WIM".into(), 5, false)
    );
    assert!(checked_fid(&valid, 0, 3, 8).is_err());
    assert!(checked_fid(&valid, 0, 4, 7).is_err());
    assert!(checked_fid(&valid[..valid.len() - 1], 0, 3, 7).is_err());
    let mut corrupt = valid;
    corrupt[42] ^= 0x01;
    assert!(checked_fid(&corrupt, 0, 3, 7).is_err());
}
#[test]
fn extent_arithmetic_and_segment_boundary_fail_closed() {
    let vol = UdfVolume {
        read_only: true,
        physical_write_authorized: false,
        descriptor_chain_verified: true,
        root_icb_tag_verified: true,
        file_tree_traversal_supported: false,
        installer_boot_verified: false,
        logical_block_bytes: 2048,
        partition_number: 7,
        partition_start_lba: 280,
        partition_blocks: 75,
        file_set_descriptor_lba: 281,
        root_icb_lba: 282,
    };
    let bytes = 370 * 2048;
    assert_eq!(extent_abs(3, 2048, &vol, bytes).unwrap(), 283 * 2048);
    assert!(extent_abs(75, 1, &vol, bytes).is_err());
    assert!(extent_abs(74, 2049, &vol, bytes).is_err());
    assert!(extent_abs(3, 0, &vol, bytes).is_err());
    let regions = [
        Extent {
            block: 3,
            bytes: 45,
        },
        Extent {
            block: 8,
            bytes: 16,
        },
    ];
    assert_eq!(logical_dir_sector(&regions, 44).unwrap(), (3, 1));
    assert_eq!(logical_dir_sector(&regions, 45).unwrap(), (8, 16));
    assert!(logical_dir_sector(&regions, 61).is_err());
}
