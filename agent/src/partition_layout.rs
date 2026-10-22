//! File-backed virtual partition table writer. No physical disk API or paths.
//! GPT metadata uses both primary and backup headers and independently checks
//! CRC-32, array boundaries and reciprocal header pointers after writing.
use crc32fast::hash;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
use thiserror::Error;
use uuid::Uuid;

pub const SECTOR: u64 = 512;
pub const MAX_DISK_BYTES: u64 = 256 * 1024 * 1024;
const FIRST_DATA_LBA: u64 = 2048;
const ENTRIES: usize = 128;
const ENTRY_SIZE: usize = 128;
const ARRAY_BYTES: usize = ENTRIES * ENTRY_SIZE;
const ARRAY_SECTORS: u64 = ARRAY_BYTES as u64 / SECTOR;
const EFI_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    Gpt,
    Mbr,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Layout {
    pub scheme: Scheme,
    pub total_lba: u64,
    pub first_lba: u64,
    pub last_lba: u64,
    pub partition_bytes: u64,
}
#[derive(Debug, Error)]
pub enum MediaError {
    #[error("virtual capacity too small, unaligned, or beyond safety cap")]
    Capacity,
    #[error("partition data or table failed integrity/boundary checks")]
    Corrupt,
    #[error("I/O failure on virtual file")]
    Io(#[from] std::io::Error),
}
pub fn plan(disk_bytes: u64, scheme: Scheme) -> Result<Layout, MediaError> {
    if !(80 * 1024 * 1024..=MAX_DISK_BYTES).contains(&disk_bytes)
        || !disk_bytes.is_multiple_of(SECTOR)
    {
        return Err(MediaError::Capacity);
    }
    let total_lba = disk_bytes / SECTOR;
    let last_lba = match scheme {
        Scheme::Gpt => total_lba.checked_sub(34),
        Scheme::Mbr => total_lba.checked_sub(1),
    }
    .ok_or(MediaError::Capacity)?;
    if last_lba <= FIRST_DATA_LBA {
        return Err(MediaError::Capacity);
    }
    Ok(Layout {
        scheme,
        total_lba,
        first_lba: FIRST_DATA_LBA,
        last_lba,
        partition_bytes: (last_lba - FIRST_DATA_LBA + 1) * SECTOR,
    })
}
fn sector_write(file: &mut File, lba: u64, data: &[u8]) -> Result<(), MediaError> {
    if !data.len().is_multiple_of(SECTOR as usize) {
        return Err(MediaError::Corrupt);
    }
    file.seek(SeekFrom::Start(
        lba.checked_mul(SECTOR).ok_or(MediaError::Corrupt)?,
    ))?;
    file.write_all(data)?;
    Ok(())
}
fn sector_read(file: &mut File, lba: u64, length: usize) -> Result<Vec<u8>, MediaError> {
    if !length.is_multiple_of(SECTOR as usize) {
        return Err(MediaError::Corrupt);
    }
    let mut bytes = vec![0; length];
    file.seek(SeekFrom::Start(
        lba.checked_mul(SECTOR).ok_or(MediaError::Corrupt)?,
    ))?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn le32(data: &[u8], index: usize) -> u32 {
    u32::from_le_bytes(data[index..index + 4].try_into().unwrap())
}
fn le64(data: &[u8], index: usize) -> u64 {
    u64::from_le_bytes(data[index..index + 8].try_into().unwrap())
}
fn put32(data: &mut [u8], index: usize, value: u32) {
    data[index..index + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(data: &mut [u8], index: usize, value: u64) {
    data[index..index + 8].copy_from_slice(&value.to_le_bytes());
}
fn mbr(layout: &Layout) -> Result<[u8; 512], MediaError> {
    let mut table = [0u8; 512];
    table[510..512].copy_from_slice(&[0x55, 0xaa]);
    let (kind, start, size) = match layout.scheme {
        Scheme::Gpt => (0xee, 1u64, (layout.total_lba - 1).min(u32::MAX as u64)),
        Scheme::Mbr => (
            0xef,
            layout.first_lba,
            layout.last_lba - layout.first_lba + 1,
        ),
    };
    table[446 + 4] = kind;
    put32(
        &mut table,
        446 + 8,
        u32::try_from(start).map_err(|_| MediaError::Capacity)?,
    );
    put32(
        &mut table,
        446 + 12,
        u32::try_from(size).map_err(|_| MediaError::Capacity)?,
    );
    Ok(table)
}
fn gpt_header(
    current: u64,
    alternate: u64,
    entries_lba: u64,
    layout: &Layout,
    disk_uuid: &[u8; 16],
    array_crc: u32,
) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..8].copy_from_slice(b"EFI PART");
    put32(&mut header, 8, 0x00010000);
    put32(&mut header, 12, 92);
    put64(&mut header, 24, current);
    put64(&mut header, 32, alternate);
    put64(&mut header, 40, FIRST_DATA_LBA);
    put64(&mut header, 48, layout.total_lba - 34);
    header[56..72].copy_from_slice(disk_uuid);
    put64(&mut header, 72, entries_lba);
    put32(&mut header, 80, ENTRIES as u32);
    put32(&mut header, 84, ENTRY_SIZE as u32);
    put32(&mut header, 88, array_crc);
    let sum = hash(&header[..92]);
    put32(&mut header, 16, sum);
    header
}
fn gpt_table(layout: &Layout) -> [u8; ARRAY_BYTES] {
    let mut table = [0u8; ARRAY_BYTES];
    table[..16].copy_from_slice(&EFI_TYPE);
    table[16..32].copy_from_slice(&Uuid::new_v4().to_bytes_le());
    put64(&mut table, 32, layout.first_lba);
    put64(&mut table, 40, layout.last_lba);
    for (i, c) in "BootNexa EFI".encode_utf16().enumerate() {
        table[56 + i * 2..58 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    table
}
pub(crate) fn write_partition_table(file: &mut File, layout: &Layout) -> Result<(), MediaError> {
    let actual = file.metadata()?.len();
    if actual != layout.total_lba * SECTOR || plan(actual, layout.scheme)? != *layout {
        return Err(MediaError::Corrupt);
    }
    sector_write(file, 0, &mbr(layout)?)?;
    if layout.scheme == Scheme::Gpt {
        let table = gpt_table(layout);
        let crc = hash(&table);
        let last = layout.total_lba - 1;
        let disk_uuid = Uuid::new_v4().to_bytes_le();
        sector_write(file, 2, &table)?;
        sector_write(file, last - ARRAY_SECTORS, &table)?;
        sector_write(file, 1, &gpt_header(1, last, 2, layout, &disk_uuid, crc))?;
        sector_write(
            file,
            last,
            &gpt_header(last, 1, last - ARRAY_SECTORS, layout, &disk_uuid, crc),
        )?;
    }
    file.sync_all()?;
    verify_partition_table(file, layout)
}
fn validate_header(
    data: &[u8],
    self_lba: u64,
    other_lba: u64,
    table_lba: u64,
    layout: &Layout,
    table: &[u8],
) -> Result<[u8; 16], MediaError> {
    if &data[..8] != b"EFI PART"
        || le32(data, 8) != 0x10000
        || le32(data, 12) != 92
        || le64(data, 24) != self_lba
        || le64(data, 32) != other_lba
        || le64(data, 40) != FIRST_DATA_LBA
        || le64(data, 48) != layout.total_lba - 34
        || le64(data, 72) != table_lba
        || le32(data, 80) != ENTRIES as u32
        || le32(data, 84) != ENTRY_SIZE as u32
        || le32(data, 88) != hash(table)
    {
        return Err(MediaError::Corrupt);
    }
    let recorded = le32(data, 16);
    let mut header = data[..92].to_vec();
    put32(&mut header, 16, 0);
    if hash(&header) != recorded || data[92..].iter().any(|&b| b != 0) {
        return Err(MediaError::Corrupt);
    }
    Ok(data[56..72].try_into().unwrap())
}
pub(crate) fn verify_partition_table(file: &mut File, layout: &Layout) -> Result<(), MediaError> {
    if plan(file.metadata()?.len(), layout.scheme)? != *layout {
        return Err(MediaError::Corrupt);
    }
    let mbr = sector_read(file, 0, 512)?;
    let expected_kind = if layout.scheme == Scheme::Gpt {
        0xee
    } else {
        0xef
    };
    if mbr[510..] != [0x55, 0xaa]
        || mbr[450] != expected_kind
        || le32(&mbr, 454) as u64
            != if layout.scheme == Scheme::Gpt {
                1
            } else {
                layout.first_lba
            }
        || le32(&mbr, 458) as u64
            != if layout.scheme == Scheme::Gpt {
                layout.total_lba - 1
            } else {
                layout.last_lba - layout.first_lba + 1
            }
    {
        return Err(MediaError::Corrupt);
    }
    if layout.scheme == Scheme::Gpt {
        let last = layout.total_lba - 1;
        let primary = sector_read(file, 1, 512)?;
        let backup = sector_read(file, last, 512)?;
        let entries = sector_read(file, 2, ARRAY_BYTES)?;
        let backup_entries = sector_read(file, last - ARRAY_SECTORS, ARRAY_BYTES)?;
        if entries != backup_entries
            || entries[..16] != EFI_TYPE
            || le64(&entries, 32) != layout.first_lba
            || le64(&entries, 40) != layout.last_lba
            || entries[128..].iter().any(|&v| v != 0)
        {
            return Err(MediaError::Corrupt);
        }
        let a = validate_header(&primary, 1, last, 2, layout, &entries)?;
        let b = validate_header(&backup, last, 1, last - ARRAY_SECTORS, layout, &entries)?;
        if a != b {
            return Err(MediaError::Corrupt);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn setup(scheme: Scheme) -> (File, Layout) {
        let layout = plan(96 * 1024 * 1024, scheme).unwrap();
        let file = tempfile::tempfile().unwrap();
        file.set_len(layout.total_lba * SECTOR).unwrap();
        (file, layout)
    }
    #[test]
    fn both_partition_tables_roundtrip() {
        for scheme in [Scheme::Gpt, Scheme::Mbr] {
            let (mut file, layout) = setup(scheme);
            write_partition_table(&mut file, &layout).unwrap();
            verify_partition_table(&mut file, &layout).unwrap();
            assert_eq!(layout.first_lba, 2048);
            assert!(layout.partition_bytes > 80 * 1024 * 1024);
        }
    }
    #[test]
    fn rejects_invalid_capacity() {
        for capacity in [
            0,
            511,
            512,
            64 * 1024 * 1024,
            257 * 1024 * 1024,
            96 * 1024 * 1024 + 1,
            u64::MAX,
        ] {
            assert!(plan(capacity, Scheme::Gpt).is_err());
        }
    }
    #[test]
    fn primary_backup_crc_and_entries_corruption_detected() {
        for lba in [
            0,
            1,
            2,
            96 * 1024 * 1024 / SECTOR - 33,
            96 * 1024 * 1024 / SECTOR - 1,
        ] {
            let (mut file, layout) = setup(Scheme::Gpt);
            write_partition_table(&mut file, &layout).unwrap();
            file.seek(SeekFrom::Start(
                lba * SECTOR + if lba == 0 { 450 } else { 0 },
            ))
            .unwrap();
            file.write_all(&[0xff]).unwrap();
            assert!(
                verify_partition_table(&mut file, &layout).is_err(),
                "lba {lba} should fail"
            );
        }
    }
    #[test]
    fn cannot_write_on_mismatched_virtual_capacity() {
        let (mut file, layout) = setup(Scheme::Gpt);
        file.set_len(100 * 1024 * 1024).unwrap();
        assert!(write_partition_table(&mut file, &layout).is_err());
    }
}
