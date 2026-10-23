use super::*;
use std::io::Cursor;

const DISK_SECTORS: usize = 370;
fn descriptor(disk: &mut [u8], lba: usize, kind: u16, set: impl FnOnce(&mut [u8])) {
    let range = lba * BLOCK as usize..(lba + 1) * BLOCK as usize;
    let data = &mut disk[range];
    data[0..2].copy_from_slice(&kind.to_le_bytes());
    data[2..4].copy_from_slice(&2u16.to_le_bytes());
    data[12..16].copy_from_slice(&(lba as u32).to_le_bytes());
    set(data);
    data[10..12].copy_from_slice(&496u16.to_le_bytes());
    let crc = crc16(&data[16..512]);
    data[8..10].copy_from_slice(&crc.to_le_bytes());
    data[4] = data[..16]
        .iter()
        .enumerate()
        .filter(|(p, _)| *p != 4)
        .fold(0u8, |sum, (_, n)| sum.wrapping_add(*n));
}
fn fixture() -> Vec<u8> {
    let mut disk = vec![0u8; DISK_SECTORS * 2048];
    descriptor(&mut disk, 256, 2, |bytes| {
        bytes[16..20].copy_from_slice(&(16u32 * 2048).to_le_bytes());
        bytes[20..24].copy_from_slice(&257u32.to_le_bytes());
    });
    descriptor(&mut disk, 257, 1, |_| {});
    descriptor(&mut disk, 258, 5, |bytes| {
        bytes[22..24].copy_from_slice(&7u16.to_le_bytes());
        bytes[188..192].copy_from_slice(&280u32.to_le_bytes());
        bytes[192..196].copy_from_slice(&75u32.to_le_bytes());
    });
    descriptor(&mut disk, 259, 6, |bytes| {
        bytes[212..216].copy_from_slice(&2048u32.to_le_bytes());
        bytes[217..236].copy_from_slice(b"*OSTA UDF Compliant");
        bytes[248..252].copy_from_slice(&2048u32.to_le_bytes());
        bytes[252..256].copy_from_slice(&1u32.to_le_bytes());
        bytes[256..258].copy_from_slice(&7u16.to_le_bytes());
        bytes[264..268].copy_from_slice(&6u32.to_le_bytes());
        bytes[268..272].copy_from_slice(&1u32.to_le_bytes());
        bytes[440] = 1;
        bytes[441] = 6;
        bytes[442..444].copy_from_slice(&1u16.to_le_bytes());
        bytes[444..446].copy_from_slice(&7u16.to_le_bytes());
    });
    descriptor(&mut disk, 260, 8, |_| {});
    descriptor(&mut disk, 281, 256, |bytes| {
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[400..404].copy_from_slice(&2048u32.to_le_bytes());
        bytes[404..408].copy_from_slice(&2u32.to_le_bytes());
        bytes[408..410].copy_from_slice(&7u16.to_le_bytes());
    });
    descriptor(&mut disk, 282, 261, |bytes| {
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        bytes[27] = 4;
        bytes[34..36].copy_from_slice(&0u16.to_le_bytes());
        bytes[168..172].copy_from_slice(&0u32.to_le_bytes());
        bytes[172..176].copy_from_slice(&8u32.to_le_bytes());
    });
    disk
}
fn retag(disk: &mut [u8], lba: usize) {
    let data = &mut disk[lba * 2048..(lba + 1) * 2048];
    let length = u16_at(data, 10) as usize;
    let crc = crc16(&data[16..16 + length]);
    data[8..10].copy_from_slice(&crc.to_le_bytes());
    data[4] = data[..16]
        .iter()
        .enumerate()
        .filter(|(p, _)| *p != 4)
        .fold(0u8, |s, (_, n)| s.wrapping_add(*n));
}
#[test]
fn valid_descriptor_chain_observed_but_ufs_file_paths_remain_unauthorized() {
    let image = fixture();
    let report = inspect(&mut Cursor::new(&image), image.len() as u64).unwrap();
    assert_eq!(report.logical_block_bytes, 2048);
    assert_eq!(report.partition_number, 7);
    assert_eq!(report.file_set_descriptor_lba, 281);
    assert_eq!(report.root_icb_lba, 282);
    assert!(report.descriptor_chain_verified && report.root_icb_tag_verified);
    assert!(!report.file_tree_traversal_supported);
    assert!(!report.physical_write_authorized && !report.installer_boot_verified);
}
#[test]
fn malformed_tags_crc_and_anchors_fail_closed() {
    for (name, lba, position) in [
        ("checksum", 256, 4),
        ("crc", 259, 45),
        ("anchor", 256, 20),
        ("partition", 258, 190),
        ("fsd", 281, 410),
        ("root", 282, 27),
    ] {
        let mut img = fixture();
        img[lba * 2048 + position] ^= 0x80;
        assert!(
            inspect(&mut Cursor::new(&img), img.len() as u64).is_err(),
            "{name}"
        );
    }
}
#[test]
fn valid_checksum_with_invalid_partition_block_and_map_fails_closed() {
    for (lba, pos, change) in [
        (258, 188, 255u8), // start outside image
        (259, 213, 0u8),   // 2048 -> 0
        (259, 441, 4u8),   // type 1 partition map length invalid
        (259, 444, 6u8),   // partition map mismatch
        (281, 404, 255u8), // root lba outside partition
    ] {
        let mut img = fixture();
        img[lba * 2048 + pos] = change;
        retag(&mut img, lba);
        assert!(
            inspect(&mut Cursor::new(&img), img.len() as u64).is_err(),
            "LBA {lba} field {pos}"
        );
    }
}
#[test]
fn crc_must_cover_descriptor_security_fields() {
    for (lba, short_crc) in [(256usize, 32u16), (259, 64), (281, 128), (282, 160)] {
        let mut img = fixture();
        let start = lba * 2048;
        img[start + 10..start + 12].copy_from_slice(&short_crc.to_le_bytes());
        retag(&mut img, lba);
        assert!(
            inspect(&mut Cursor::new(&img), img.len() as u64).is_err(),
            "truncated CRC must not grant UDF metadata qualification for LBA {lba}"
        );
    }
}
#[test]
fn missing_root_or_truncated_image_is_rejected() {
    let image = fixture();
    assert!(inspect(&mut Cursor::new(&image[..100_000]), 100_000).is_err());
    let mut bad = image;
    bad[282 * 2048 + 168..282 * 2048 + 172].copy_from_slice(&u32::MAX.to_le_bytes());
    retag(&mut bad, 282);
    assert!(inspect(&mut Cursor::new(&bad), bad.len() as u64).is_err());
}
