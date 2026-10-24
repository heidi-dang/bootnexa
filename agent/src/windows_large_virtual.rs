//! Anonymous sparse large-capacity GPT/ESP layout; no USB, NTFS writer,
//! filesystem payload, Windows Setup execution or exported disk images.
use crate::partition_layout::MediaError;
use crc32fast::hash;
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};
use uuid::Uuid;

const SECTOR: u64 = 512;
const ALIGN: u64 = 2048;
const ESP_BYTES: u64 = 256 * 1024 * 1024;
const ENTRIES: usize = 128;
const ENTRY_BYTES: usize = 128;
const TABLE_BYTES: usize = ENTRIES * ENTRY_BYTES;
const ARRAY_SECTORS: u64 = TABLE_BYTES as u64 / SECTOR;
pub const MIN_GIB: u32 = 1;
pub const MAX_GIB: u32 = 24;
const EFI_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
const DATA_GUID: [u8; 16] = [
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LargePlan {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub windows_setup_boot_verified: bool,
    pub windows_installer_compatible: bool,
    pub boot_execution_verified: bool,
    pub full_disk_sha256_verified: bool,
    pub payload_filesystem_formatted: bool,
    pub ntfs_writer_available: bool,
    pub esp_fat32_verified: bool,
    pub primary_and_backup_gpt_verified: bool,
    pub reserved_payload_sampled_zero: bool,
    pub disk_bytes: u64,
    pub esp_first_lba: u64,
    pub esp_last_lba: u64,
    pub esp_bytes: u64,
    pub reserved_payload_first_lba: u64,
    pub reserved_payload_last_lba: u64,
    pub reserved_payload_bytes: u64,
    pub metadata_sha256: String,
}
#[derive(Clone, Copy, Debug)]
struct Bounds {
    disk: u64,
    total: u64,
    esp_first: u64,
    esp_last: u64,
    data_first: u64,
    data_last: u64,
}
fn bounds(gib: u32) -> Result<Bounds, MediaError> {
    if !(MIN_GIB..=MAX_GIB).contains(&gib) {
        return Err(MediaError::Capacity);
    }
    let disk = u64::from(gib) * 1024 * 1024 * 1024;
    let total = disk / SECTOR;
    let esp_first = ALIGN;
    let esp_last = esp_first + ESP_BYTES / SECTOR - 1;
    let data_first = esp_last + 1;
    let data_last = total.checked_sub(34).ok_or(MediaError::Capacity)?;
    if data_first >= data_last || !data_first.is_multiple_of(ALIGN) {
        return Err(MediaError::Capacity);
    }
    Ok(Bounds {
        disk,
        total,
        esp_first,
        esp_last,
        data_first,
        data_last,
    })
}
fn put32(out: &mut [u8], offset: usize, n: u32) {
    out[offset..offset + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(out: &mut [u8], offset: usize, n: u64) {
    out[offset..offset + 8].copy_from_slice(&n.to_le_bytes());
}
fn at64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn at32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn make_array(b: Bounds) -> [u8; TABLE_BYTES] {
    let mut table = [0u8; TABLE_BYTES];
    for (index, ty, start, end, name) in [
        (0, EFI_GUID, b.esp_first, b.esp_last, "BootNexa EFI"),
        (1, DATA_GUID, b.data_first, b.data_last, "Unformatted Data"),
    ] {
        let entry = &mut table[index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES];
        entry[..16].copy_from_slice(&ty);
        entry[16..32].copy_from_slice(&Uuid::new_v4().to_bytes_le());
        put64(entry, 32, start);
        put64(entry, 40, end);
        for (i, unit) in name.encode_utf16().enumerate() {
            entry[56 + i * 2..58 + i * 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    table
}
fn header(
    b: Bounds,
    current: u64,
    alternate: u64,
    array_lba: u64,
    guid: &[u8; 16],
    array_crc: u32,
) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..8].copy_from_slice(b"EFI PART");
    put32(&mut h, 8, 0x10000);
    put32(&mut h, 12, 92);
    put64(&mut h, 24, current);
    put64(&mut h, 32, alternate);
    put64(&mut h, 40, 34);
    put64(&mut h, 48, b.total - 34);
    h[56..72].copy_from_slice(guid);
    put64(&mut h, 72, array_lba);
    put32(&mut h, 80, ENTRIES as u32);
    put32(&mut h, 84, ENTRY_BYTES as u32);
    put32(&mut h, 88, array_crc);
    let crc = hash(&h[..92]);
    put32(&mut h, 16, crc);
    h
}
fn write_bytes(file: &mut File, offset: u64, data: &[u8]) -> Result<(), MediaError> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;
    Ok(())
}
fn read_bytes(file: &mut File, offset: u64, out: &mut [u8]) -> Result<(), MediaError> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(out)?;
    Ok(())
}
fn write_gpt(file: &mut File, b: Bounds) -> Result<(), MediaError> {
    if file.metadata()?.len() != b.disk {
        return Err(MediaError::Corrupt);
    }
    let mut mbr = [0u8; 512];
    mbr[450] = 0xee;
    put32(&mut mbr, 454, 1);
    put32(
        &mut mbr,
        458,
        u32::try_from(b.total - 1).map_err(|_| MediaError::Capacity)?,
    );
    mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
    write_bytes(file, 0, &mbr)?;
    let table = make_array(b);
    let crc = hash(&table);
    let guid = Uuid::new_v4().to_bytes_le();
    let last = b.total - 1;
    write_bytes(file, 2 * SECTOR, &table)?;
    write_bytes(file, (last - ARRAY_SECTORS) * SECTOR, &table)?;
    write_bytes(file, SECTOR, &header(b, 1, last, 2, &guid, crc))?;
    write_bytes(
        file,
        last * SECTOR,
        &header(b, last, 1, last - ARRAY_SECTORS, &guid, crc),
    )?;
    Ok(())
}
fn check_header(
    header: &[u8; 512],
    b: Bounds,
    here: u64,
    there: u64,
    table_lba: u64,
    table: &[u8],
) -> Result<[u8; 16], MediaError> {
    if &header[..8] != b"EFI PART"
        || at32(header, 8) != 0x10000
        || at32(header, 12) != 92
        || at64(header, 24) != here
        || at64(header, 32) != there
        || at64(header, 40) != 34
        || at64(header, 48) != b.total - 34
        || at64(header, 72) != table_lba
        || at32(header, 80) != ENTRIES as u32
        || at32(header, 84) != ENTRY_BYTES as u32
        || at32(header, 88) != hash(table)
        || header[92..].iter().any(|&n| n != 0)
        || header[20..24].iter().any(|&n| n != 0)
    {
        return Err(MediaError::Corrupt);
    }
    let mut copy = *header;
    put32(&mut copy, 16, 0);
    if hash(&copy[..92]) != at32(header, 16) {
        return Err(MediaError::Corrupt);
    }
    Ok(header[56..72].try_into().unwrap())
}
fn verify_gpt(file: &mut File, b: Bounds) -> Result<String, MediaError> {
    if file.metadata()?.len() != b.disk {
        return Err(MediaError::Corrupt);
    }
    let mut mbr = [0u8; 512];
    read_bytes(file, 0, &mut mbr)?;
    if mbr[510..512] != [0x55, 0xaa]
        || mbr[450] != 0xee
        || at32(&mbr, 454) != 1
        || u64::from(at32(&mbr, 458)) != b.total - 1
        || mbr[..446].iter().any(|&v| v != 0)
        || mbr[446..450].iter().any(|&v| v != 0)
        || mbr[451..454].iter().any(|&v| v != 0)
        || mbr[462..510].iter().any(|&v| v != 0)
    {
        return Err(MediaError::Corrupt);
    }
    let mut primary = [0u8; 512];
    let mut backup = [0u8; 512];
    let mut entries = [0u8; TABLE_BYTES];
    let mut secondary = [0u8; TABLE_BYTES];
    read_bytes(file, SECTOR, &mut primary)?;
    read_bytes(file, (b.total - 1) * SECTOR, &mut backup)?;
    read_bytes(file, 2 * SECTOR, &mut entries)?;
    read_bytes(file, (b.total - 1 - ARRAY_SECTORS) * SECTOR, &mut secondary)?;
    if entries != secondary || entries[2 * ENTRY_BYTES..].iter().any(|&v| v != 0) {
        return Err(MediaError::Corrupt);
    }
    for (i, ty, start, end) in [
        (0, EFI_GUID, b.esp_first, b.esp_last),
        (1, DATA_GUID, b.data_first, b.data_last),
    ] {
        let entry = &entries[i * ENTRY_BYTES..(i + 1) * ENTRY_BYTES];
        if entry[..16] != ty
            || at64(entry, 32) != start
            || at64(entry, 40) != end
            || entry[16..32].iter().all(|&v| v == 0)
        {
            return Err(MediaError::Corrupt);
        }
    }
    if entries[16..32] == entries[ENTRY_BYTES + 16..ENTRY_BYTES + 32] {
        return Err(MediaError::Corrupt);
    }
    let a = check_header(&primary, b, 1, b.total - 1, 2, &entries)?;
    let z = check_header(
        &backup,
        b,
        b.total - 1,
        1,
        b.total - 1 - ARRAY_SECTORS,
        &entries,
    )?;
    if a != z || a.iter().all(|&v| v == 0) {
        return Err(MediaError::Corrupt);
    }
    let mut digest = Sha256::new();
    for part in [
        &mbr[..],
        &primary[..],
        &entries[..],
        &secondary[..],
        &backup[..],
    ] {
        digest.update(part);
    }
    Ok(hex::encode(digest.finalize()))
}
struct Region<'a> {
    file: &'a mut File,
    base: u64,
    length: u64,
    pos: u64,
}
impl Region<'_> {
    fn seek_to(&mut self, value: u64) -> io::Result<u64> {
        if value > self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "partition bounds",
            ));
        }
        self.pos = value;
        Ok(value)
    }
}
impl Read for Region<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.length - self.pos).min(buf.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(self.base + self.pos))?;
        let got = self.file.read(&mut buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
}
impl Write for Region<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = (self.length - self.pos).min(buf.len() as u64) as usize;
        if n == 0 && !buf.is_empty() {
            return Err(io::Error::other("partition capacity"));
        }
        self.file.seek(SeekFrom::Start(self.base + self.pos))?;
        let got = self.file.write(&buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for Region<'_> {
    fn seek(&mut self, which: SeekFrom) -> io::Result<u64> {
        let next = match which {
            SeekFrom::Start(x) => i128::from(x),
            SeekFrom::Current(x) => i128::from(self.pos) + i128::from(x),
            SeekFrom::End(x) => i128::from(self.length) + i128::from(x),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "partition boundary",
            ));
        }
        self.seek_to(next as u64)
    }
}
pub struct LargeSparseDisk {
    file: File,
    b: Bounds,
}
impl LargeSparseDisk {
    pub fn new(gib: u32) -> Result<Self, MediaError> {
        // Only Linux sparse anonymous tmpfiles are qualified here. Windows
        // filesystems may allocate the full nominal size at SetEndOfFile.
        let b = bounds(gib)?;
        if !cfg!(target_os = "linux") {
            return Err(MediaError::Capacity);
        }
        let mut file = tempfile::tempfile()?;
        file.set_len(b.disk)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if file.metadata()?.blocks().saturating_mul(512) > 16 * 1024 * 1024 {
                return Err(MediaError::Capacity);
            }
        }
        write_gpt(&mut file, b)?;
        {
            let region = Region {
                file: &mut file,
                base: b.esp_first * SECTOR,
                length: ESP_BYTES,
                pos: 0,
            };
            fatfs::format_volume(
                region,
                FormatVolumeOptions::new()
                    .fat_type(FatType::Fat32)
                    .bytes_per_cluster(2048)
                    .volume_label(*b"BOOTNEXA   "),
            )?;
        }
        file.sync_all()?;
        let mut disk = Self { file, b };
        disk.verify()?;
        Ok(disk)
    }
    pub fn verify(&mut self) -> Result<LargePlan, MediaError> {
        let metadata_sha256 = verify_gpt(&mut self.file, self.b)?;
        // Explicitly check three bounded sentinel sectors, not the complete
        // reserved filesystem. This is not a full-disk integrity assertion.
        for lba in [
            self.b.data_first,
            self.b.data_first + (self.b.data_last - self.b.data_first) / 2,
            self.b.data_last,
        ] {
            let mut sample = [0u8; 512];
            read_bytes(&mut self.file, lba * SECTOR, &mut sample)?;
            if sample.iter().any(|&value| value != 0) {
                return Err(MediaError::Corrupt);
            }
        }
        let view = Region {
            file: &mut self.file,
            base: self.b.esp_first * SECTOR,
            length: ESP_BYTES,
            pos: 0,
        };
        let fs = FileSystem::new(view, FsOptions::new())?;
        if fs.fat_type() != FatType::Fat32 {
            return Err(MediaError::Corrupt);
        }
        drop(fs);
        Ok(LargePlan {
            virtual_only: true,
            physical_write_authorized: false,
            windows_setup_boot_verified: false,
            windows_installer_compatible: false,
            boot_execution_verified: false,
            full_disk_sha256_verified: false,
            payload_filesystem_formatted: false,
            ntfs_writer_available: false,
            esp_fat32_verified: true,
            primary_and_backup_gpt_verified: true,
            reserved_payload_sampled_zero: true,
            disk_bytes: self.b.disk,
            esp_first_lba: self.b.esp_first,
            esp_last_lba: self.b.esp_last,
            esp_bytes: ESP_BYTES,
            reserved_payload_first_lba: self.b.data_first,
            reserved_payload_last_lba: self.b.data_last,
            reserved_payload_bytes: (self.b.data_last - self.b.data_first + 1) * SECTOR,
            metadata_sha256,
        })
    }
    #[cfg(all(test, target_os = "linux"))]
    fn overwrite_at(&mut self, offset: u64, data: &[u8]) -> Result<(), MediaError> {
        write_bytes(&mut self.file, offset, data)
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn capacity_and_sparse_gpt_esp_contract() {
        for n in [0, 25, u32::MAX] {
            assert!(bounds(n).is_err());
        }
        for n in [1, 8, 24] {
            let mut disk = LargeSparseDisk::new(n).unwrap();
            let proof = disk.verify().unwrap();
            assert_eq!(proof.disk_bytes, u64::from(n) * 1024 * 1024 * 1024);
            assert!(proof.primary_and_backup_gpt_verified && proof.esp_fat32_verified);
            assert!(!proof.physical_write_authorized && !proof.windows_setup_boot_verified);
            assert!(!proof.ntfs_writer_available && !proof.payload_filesystem_formatted);
            assert!(!proof.full_disk_sha256_verified);
            assert!(proof.reserved_payload_sampled_zero);
            assert_eq!(proof.esp_last_lba + 1, proof.reserved_payload_first_lba);
            assert!(proof.reserved_payload_bytes > 0);
            let mut end = [0u8; 512];
            read_bytes(&mut disk.file, (disk.b.total - 1) * SECTOR, &mut end).unwrap();
            assert_eq!(&end[..8], b"EFI PART");
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn tampering_either_gpt_copy_and_bad_file_size_fails() {
        for offset in [
            0,
            SECTOR,
            2 * SECTOR,
            (8 * 1024 * 1024 * 1024u64 / SECTOR - 1 - ARRAY_SECTORS) * SECTOR,
            (8 * 1024 * 1024 * 1024u64 / SECTOR - 1) * SECTOR,
        ] {
            let mut disk = LargeSparseDisk::new(8).unwrap();
            disk.overwrite_at(offset, &[0xff]).unwrap();
            assert!(disk.verify().is_err(), "corruption at byte {offset}");
        }
        let mut disk = LargeSparseDisk::new(8).unwrap();
        disk.file.set_len(4 * 1024 * 1024 * 1024).unwrap();
        assert!(disk.verify().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_payload_sentinel_mutation_blocks_qualification() {
        let mut disk = LargeSparseDisk::new(8).unwrap();
        disk.overwrite_at(disk.b.data_first * SECTOR, &[0x5a])
            .unwrap();
        assert!(disk.verify().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn partition_view_rejects_out_of_bounds_writes() {
        let mut disk = LargeSparseDisk::new(1).unwrap();
        let mut area = Region {
            file: &mut disk.file,
            base: disk.b.esp_first * SECTOR,
            length: ESP_BYTES,
            pos: 0,
        };
        assert!(area.seek(SeekFrom::End(1)).is_err());
        area.seek(SeekFrom::End(0)).unwrap();
        assert!(area.write_all(&[0xff]).is_err());
        disk.verify().unwrap();
    }
}
