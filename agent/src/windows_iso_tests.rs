#[cfg(test)]
mod tests {
    use super::super::*;
    use std::io::Cursor;

    fn wim_fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; WIM_HEADER_BYTES];
        bytes[..8].copy_from_slice(b"MSWIM\0\0\0");
        bytes[8..12].copy_from_slice(&(208u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(0x10d00u32).to_le_bytes());
        bytes[40..42].copy_from_slice(&(1u16).to_le_bytes());
        bytes[42..44].copy_from_slice(&(1u16).to_le_bytes());
        bytes[44..48].copy_from_slice(&(2u32).to_le_bytes());
        bytes
    }
    fn entry(bytes: &[u8]) -> IsoFile {
        IsoFile {
            path: "SOURCES/BOOT.WIM".to_string(),
            offset: 0,
            length: bytes.len() as u64,
        }
    }
    #[test]
    fn windows_wim_headers_only_validate_structure_not_installer_execution() {
        let bytes = wim_fixture();
        let header = parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).unwrap();
        assert_eq!(header.image_count, 2);
        assert_eq!(header.file_bytes, WIM_HEADER_BYTES as u64);
        assert_eq!(header.part_number, 1);
        assert_eq!(header.total_parts, 1);
    }
    #[test]
    fn windows_wim_header_fails_closed_on_malformed_or_spanned_headers() {
        for pos in [0, 8, 12, 40, 42, 44] {
            let mut bytes = wim_fixture();
            bytes[pos] = if pos == 44 { 0 } else { 0xff };
            assert!(
                parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_err(),
                "malformed byte at {pos} must fail"
            );
        }
        let bytes = vec![0u8; 160];
        assert!(parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_err());
    }
    #[test]
    fn solid_esd_header_is_metadata_only_and_boot_index_is_bounded() {
        let mut bytes = wim_fixture();
        bytes[12..16].copy_from_slice(&0xe00u32.to_le_bytes());
        bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
        let header = parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).unwrap();
        assert!(header.solid_archive);
        assert_eq!(header.boot_index, 1);
        assert!(!header.resources_verified);
        bytes[120..124].copy_from_slice(&3u32.to_le_bytes());
        assert!(parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_err());
        bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x08u32.to_le_bytes());
        assert!(parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_err());
        bytes[16..20].copy_from_slice(&0x40u32.to_le_bytes());
        assert!(parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_err());
    }
    #[test]
    fn wim_outer_resource_ranges_are_bounded_without_claiming_resource_integrity() {
        let mut bytes = wim_fixture();
        bytes.resize(1024, 0);
        // Lookup table descriptor: 32 compressed bytes at offset 256.
        bytes[48..56].copy_from_slice(&32u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&256u64.to_le_bytes());
        bytes[64..72].copy_from_slice(&64u64.to_le_bytes());
        let report = parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).unwrap();
        assert!(report.resource_ranges_bounded);
        assert!(!report.resources_verified);
        // Truncated resource spills past EOF.
        bytes[56..64].copy_from_slice(&1010u64.to_le_bytes());
        assert!(parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_err());
        bytes[56..64].copy_from_slice(&256u64.to_le_bytes());
        // XML resource overlaps lookup table but has internally valid bounds.
        bytes[72..80].copy_from_slice(&16u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&260u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&16u64.to_le_bytes());
        assert!(parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_err());
        bytes[80..88].copy_from_slice(&512u64.to_le_bytes());
        assert!(parse_wim(&mut Cursor::new(&bytes), &entry(&bytes)).is_ok());
    }
    #[test]
    fn rejects_untrusted_efi_and_reports_no_boot_success() {
        let bytes = vec![0u8; 512];
        let efi = IsoFile {
            path: "EFI/BOOT/BOOTX64.EFI".into(),
            offset: 0,
            length: bytes.len() as u64,
        };
        assert!(!check_efi_x64(&mut Cursor::new(bytes), &efi).unwrap());
    }
}
