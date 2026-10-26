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
    pub payload_fat32_verified: bool,
    pub disk_bytes: u64,
    pub esp_first_lba: u64,
    pub esp_last_lba: u64,
    pub esp_bytes: u64,
    pub reserved_payload_first_lba: u64,
    pub reserved_payload_last_lba: u64,
    pub reserved_payload_bytes: u64,
    pub metadata_sha256: String,
}
/// The only staged payload is a fixed EFI loader test path in a private
/// anonymous FAT32 partition. A structurally valid PE header is NOT trust.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LargeEfiReceipt {
    pub layout: LargePlan,
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub windows_setup_boot_verified: bool,
    pub efi_structure_verified: bool,
    pub efi_executability_verified: bool,
    pub efi_source_bytes: u64,
    pub efi_source_sha256: String,
    pub efi_fat32_readback_sha256: String,
    pub efi_source_unchanged: bool,
}
const MAX_EFI_BYTES: usize = 8 * 1024 * 1024;
fn read_source_efi(source: &std::path::Path) -> Result<Vec<u8>, MediaError> {
    // Only a read-only, regular local file; no source device handles or links.
    if !std::fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(MediaError::Corrupt);
    }
    let file = File::open(source)?;
    let length = file.metadata()?.len();
    if !(256..=MAX_EFI_BYTES as u64).contains(&length) {
        return Err(MediaError::Capacity);
    }
    let mut data = Vec::with_capacity(length as usize);
    file.take(MAX_EFI_BYTES as u64 + 1).read_to_end(&mut data)?;
    if data.len() != length as usize {
        return Err(MediaError::Corrupt);
    }
    Ok(data)
}
fn ensure_x64_efi_header(data: &[u8]) -> Result<(), MediaError> {
    if data.len() < 0x100 || &data[..2] != b"MZ" {
        return Err(MediaError::Corrupt);
    }
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    if pe.checked_add(0x60).is_none_or(|end| end > data.len())
        || &data[pe..pe + 4] != b"PE\0\0"
        || data[pe + 4..pe + 6] != [0x64, 0x86]
        || data[pe + 24..pe + 26] != [0x0b, 0x02]
        || data[pe + 24 + 68..pe + 24 + 70] != [10, 0]
    {
        return Err(MediaError::Corrupt);
    }
    Ok(())
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
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStageReport {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub windows_setup_boot_verified: bool,
    pub installer_compatible_verified: bool,
    pub full_disk_sha256_verified: bool,
    pub payload_fat32_verified: bool,
    pub source_bytes: u64,
    pub source_sha256: String,
    pub fat32_readback_sha256: String,
    pub source_after_sha256: String,
    pub staged_path: &'static str,
    pub primary_and_backup_gpt_verified: bool,
}
/// Synthetic-only split-WIM receipt. A verified SWM archive does not prove
/// compatibility with an official Windows Setup ISO or EFI bootability.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LargeSwmReceipt {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub windows_setup_boot_verified: bool,
    pub installer_compatible_verified: bool,
    pub full_disk_sha256_verified: bool,
    pub split_archive_preverified: bool,
    pub payload_fat32_verified: bool,
    pub gpt_integrity_verified: bool,
    pub disk_bytes: u64,
    pub total_staged_bytes: u64,
    pub available_host_bytes_at_admission: u64,
    pub required_free_host_bytes_at_admission: u64,
    pub host_storage_admission_passed: bool,
    pub full_size_virtual_profile_requested: bool,
    pub persistent_disk_image_produced: bool,
    pub staged_parts: Vec<crate::swm_qualification::SplitPart>,
}

/// Developer-only verified SWM + bounded ISO-file stream placed together
/// on ONE anonymous GPT/FAT32 disk. No Microsoft publisher or boot proof.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CombinedInstallerTreeReceipt {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub installer_compatible_verified: bool,
    pub windows_setup_boot_verified: bool,
    pub full_disk_sha256_verified: bool,
    pub persistent_disk_image_produced: bool,
    pub complete_source_iso_verified: bool,
    pub virtual_combined_layout_verified: bool,
    pub efi_fat32_verified: bool,
    pub payload_fat32_verified: bool,
    pub gpt_integrity_verified: bool,
    pub swm: LargeSwmReceipt,
    pub iso_files: IsoStreamReceipt,
}

/// Receipt for strictly bounded ISO-file bytes transferred via stdin into
/// anonymous GPT/FAT32 partitions. Neither an installer disk nor boot proof.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IsoStreamReceipt {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub windows_setup_boot_verified: bool,
    pub installer_compatible_verified: bool,
    pub full_disk_sha256_verified: bool,
    pub source_iso_unchanged_verified: bool,
    pub gpt_integrity_verified: bool,
    pub efi_fat32_verified: bool,
    pub payload_fat32_verified: bool,
    pub staged_file_count: usize,
    pub staged_bytes: u64,
    pub files: Vec<IsoStagedFile>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IsoStagedFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub partition: &'static str,
    pub independent_fat32_readback_verified: bool,
}
/// Separate full-size virtual profile. This does not authorize USB writes,
/// prove Setup boot, or export a disk image.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SwmStageProfile {
    BoundedDemo,
    FullSizeVirtual,
}

/// Fail closed on FAT32 occupancy, arithmetic and conservative host headroom.
/// The actual anonymous tempfile's free bytes are read separately with
/// fstatvfs immediately before data staging; this is NOT space reservation.
#[cfg(target_os = "linux")]
fn swm_admission_requirement(
    total: u64,
    payload_capacity: u64,
    profile: SwmStageProfile,
) -> Result<u64, MediaError> {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    let limit = match profile {
        SwmStageProfile::BoundedDemo => GIB,
        SwmStageProfile::FullSizeVirtual => 16 * GIB,
    };
    if total == 0 || total > limit {
        return Err(MediaError::Capacity);
    }
    let occupied = total
        .checked_add(total / 4)
        .and_then(|v| v.checked_add(64 * MIB))
        .ok_or(MediaError::Capacity)?;
    if occupied > payload_capacity {
        return Err(MediaError::Capacity);
    }
    let free_margin = match profile {
        SwmStageProfile::BoundedDemo => 256 * MIB,
        SwmStageProfile::FullSizeVirtual => GIB,
    };
    let twice = total.checked_mul(2).ok_or(MediaError::Capacity)?;
    Ok(twice
        .checked_add(free_margin)
        .ok_or(MediaError::Capacity)?
        .max(512 * MIB))
}

pub struct LargeSparseDisk {
    file: File,
    b: Bounds,
    payload_fat32: bool,
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
        let mut disk = Self {
            file,
            b,
            payload_fat32: false,
        };
        disk.verify()?;
        Ok(disk)
    }
    /// Consumes BNXI0001 framed, bounded ISO *test data* from stdin.
    /// No device handles and no persisted disk; the caller must independently
    /// re-verify the ISO and hashes before and after this transfer.
    pub fn stage_iso_stream(
        &mut self,
        input: &mut impl Read,
    ) -> Result<IsoStreamReceipt, MediaError> {
        self.stage_iso_stream_mode(input, false)
    }

    /// An explicitly selected, synthetic-only virtual tree path. The SWM
    /// archive is verified and staged first, then remaining ISO files are
    /// streamed into the SAME anonymous disk. All disk state is discarded.
    pub fn stage_combined_windows_tree(
        &mut self,
        split_dir: &std::path::Path,
        input: &mut impl Read,
    ) -> Result<CombinedInstallerTreeReceipt, MediaError> {
        let original_gpt = verify_gpt(&mut self.file, self.b)?;
        let swm = self.stage_fullsize_swm_virtual(split_dir)?;
        // Admit bounded extra stream headroom early; actual stream totals
        // are checked against FAT32 capacity below. Mid-stage disk pressure
        // still fails closed, without persisting any exported disk image.
        self.admit_swm_storage(
            swm.total_staged_bytes
                .checked_add(128 * 1024 * 1024)
                .ok_or(MediaError::Capacity)?,
            SwmStageProfile::FullSizeVirtual,
        )?;
        let iso_files = self.stage_iso_stream_mode(input, true)?;
        let total = swm
            .total_staged_bytes
            .checked_add(iso_files.staged_bytes)
            .ok_or(MediaError::Capacity)?;
        if total > 16 * 1024 * 1024 * 1024 {
            return Err(MediaError::Capacity);
        }
        let payload_capacity = (self.b.data_last - self.b.data_first + 1)
            .checked_mul(SECTOR)
            .ok_or(MediaError::Capacity)?;
        let _ =
            swm_admission_requirement(total, payload_capacity, SwmStageProfile::FullSizeVirtual)?;
        // SWM source is reverified after all other ISO files have been copied,
        // and SWM entries are reopened independently from final FAT32 state.
        let after = crate::swm_qualification::verify_existing_split(split_dir)
            .map_err(|_| MediaError::Corrupt)?;
        if after.len() != swm.staged_parts.len()
            || after.iter().zip(&swm.staged_parts).any(|(a, b)| {
                a.filename != b.filename || a.bytes != b.bytes || a.sha256 != b.sha256
            })
        {
            return Err(MediaError::Corrupt);
        }
        {
            let region = Region {
                file: &mut self.file,
                base: self.b.data_first * SECTOR,
                length: (self.b.data_last - self.b.data_first + 1) * SECTOR,
                pos: 0,
            };
            let fs = FileSystem::new(region, FsOptions::new())?;
            let sources = fs.root_dir().open_dir("SOURCES")?;
            let mut buf = [0u8; 65_536];
            for part in &after {
                let mut file = sources.open_file(&part.filename)?;
                let mut hash = Sha256::new();
                let mut remaining = part.bytes;
                while remaining > 0 {
                    let n = remaining.min(buf.len() as u64) as usize;
                    file.read_exact(&mut buf[..n])?;
                    hash.update(&buf[..n]);
                    remaining -= n as u64;
                }
                if file.read(&mut buf[..1])? != 0 || hex::encode(hash.finalize()) != part.sha256 {
                    return Err(MediaError::Corrupt);
                }
            }
        }
        if verify_gpt(&mut self.file, self.b)? != original_gpt {
            return Err(MediaError::Corrupt);
        }
        let proof = self.verify()?;
        Ok(CombinedInstallerTreeReceipt {
            virtual_only: true,
            physical_write_authorized: false,
            installer_compatible_verified: false,
            windows_setup_boot_verified: false,
            full_disk_sha256_verified: false,
            persistent_disk_image_produced: false,
            complete_source_iso_verified: false,
            virtual_combined_layout_verified: true,
            efi_fat32_verified: proof.esp_fat32_verified,
            payload_fat32_verified: proof.payload_fat32_verified,
            gpt_integrity_verified: proof.primary_and_backup_gpt_verified,
            swm,
            iso_files,
        })
    }

    fn stage_iso_stream_mode(
        &mut self,
        input: &mut impl Read,
        with_verified_swm: bool,
    ) -> Result<IsoStreamReceipt, MediaError> {
        // Larger 2-GiB ceiling is exclusively available for the combined
        // tree after verified SWM admission. Legacy BNXI0001 stays bounded.
        let max_file: u64 = if with_verified_swm {
            1024 * 1024 * 1024
        } else {
            128 * 1024 * 1024
        };
        let max_total: u64 = if with_verified_swm {
            2 * 1024 * 1024 * 1024
        } else {
            384 * 1024 * 1024
        };
        let max_count: usize = if with_verified_swm { 4096 } else { 128 };
        if !self.payload_fat32 {
            return Err(MediaError::Corrupt);
        }
        let original_gpt = verify_gpt(&mut self.file, self.b)?;
        let mut magic = [0u8; 8];
        input.read_exact(&mut magic)?;
        if magic
            != *if with_verified_swm {
                b"BNXI0002"
            } else {
                b"BNXI0001"
            }
        {
            return Err(MediaError::Corrupt);
        }
        let mut count_bytes = [0u8; 2];
        input.read_exact(&mut count_bytes)?;
        let count = usize::from(u16::from_le_bytes(count_bytes));
        if !(4..=max_count).contains(&count) {
            return Err(MediaError::Capacity);
        }
        let mut seen = std::collections::HashSet::new();
        let mut dirs = std::collections::HashSet::new();
        let mut total = 0u64;
        let mut staged = Vec::with_capacity(count);
        for _ in 0..count {
            let mut two = [0u8; 2];
            input.read_exact(&mut two)?;
            let len = usize::from(u16::from_le_bytes(two));
            if len == 0 || len > 240 {
                return Err(MediaError::Capacity);
            }
            let mut name = vec![0u8; len];
            input.read_exact(&mut name)?;
            let path = String::from_utf8(name).map_err(|_| MediaError::Corrupt)?;
            let components = path.split('/').collect::<Vec<_>>();
            if components.len() > 16
                || components.iter().any(|s| {
                    s.is_empty()
                        || s.len() > 100
                        || s.starts_with(['-', ' '])
                        || s.ends_with(['.', ' '])
                        || !s
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                        || matches!(
                            s.split('.')
                                .next()
                                .unwrap_or("")
                                .to_ascii_uppercase()
                                .as_str(),
                            "CON"
                                | "PRN"
                                | "AUX"
                                | "NUL"
                                | "COM1"
                                | "COM2"
                                | "COM3"
                                | "COM4"
                                | "COM5"
                                | "COM6"
                                | "COM7"
                                | "COM8"
                                | "COM9"
                                | "LPT1"
                                | "LPT2"
                                | "LPT3"
                                | "LPT4"
                                | "LPT5"
                                | "LPT6"
                                | "LPT7"
                                | "LPT8"
                                | "LPT9"
                        )
                })
            {
                return Err(MediaError::Corrupt);
            }
            let folded = path.to_ascii_lowercase();
            // Only the native wimlib-verified SWM path may create any
            // SOURCES/install*.swm. Mixing an old WIM/ESD and split WIM
            // is never accepted by the combined profile.
            if with_verified_swm
                && (folded == "sources/install.wim"
                    || folded == "sources/install.esd"
                    || (folded.starts_with("sources/install") && folded.ends_with(".swm")))
            {
                return Err(MediaError::Corrupt);
            }
            if !seen.insert(folded.clone()) || dirs.contains(&folded) {
                return Err(MediaError::Corrupt);
            }
            let mut prefix = String::new();
            for component in components.iter().take(components.len() - 1) {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                let lower = prefix.to_ascii_lowercase();
                if seen.contains(&lower) {
                    return Err(MediaError::Corrupt);
                }
                dirs.insert(lower);
            }
            let mut bytes = [0u8; 8];
            input.read_exact(&mut bytes)?;
            let length = u64::from_le_bytes(bytes);
            total = total.checked_add(length).ok_or(MediaError::Capacity)?;
            if length > max_file || total > max_total {
                return Err(MediaError::Capacity);
            }
            let mut digest = [0u8; 32];
            input.read_exact(&mut digest)?;
            let part_efi = components[0].eq_ignore_ascii_case("EFI");
            let (base, limit) = if part_efi {
                (self.b.esp_first * SECTOR, ESP_BYTES)
            } else {
                (
                    self.b.data_first * SECTOR,
                    (self.b.data_last - self.b.data_first + 1) * SECTOR,
                )
            };
            let readback = {
                let view = Region {
                    file: &mut self.file,
                    base,
                    length: limit,
                    pos: 0,
                };
                let fs = FileSystem::new(view, FsOptions::new())?;
                if fs.fat_type() != FatType::Fat32 {
                    return Err(MediaError::Corrupt);
                }
                let root = fs.root_dir();
                let mut path_prefix = String::new();
                for dir in components.iter().take(components.len() - 1) {
                    if !path_prefix.is_empty() {
                        path_prefix.push('/');
                    }
                    path_prefix.push_str(dir);
                    if root.open_dir(&path_prefix).is_err() {
                        root.create_dir(&path_prefix)?;
                    }
                }
                if root.open_file(&path).is_ok() {
                    return Err(MediaError::Corrupt);
                }
                let mut dest = root.create_file(&path)?;
                let mut left = length;
                let mut copy_sha = Sha256::new();
                let mut buf = [0u8; 65536];
                while left > 0 {
                    let take = left.min(buf.len() as u64) as usize;
                    input.read_exact(&mut buf[..take])?;
                    dest.write_all(&buf[..take])?;
                    copy_sha.update(&buf[..take]);
                    left -= take as u64;
                }
                if copy_sha.finalize().as_slice() != digest {
                    return Err(MediaError::Corrupt);
                }
                dest.flush()?;
                drop(dest);
                let mut verify = root.open_file(&path)?;
                let mut left = length;
                let mut sha = Sha256::new();
                while left > 0 {
                    let take = left.min(buf.len() as u64) as usize;
                    verify.read_exact(&mut buf[..take])?;
                    sha.update(&buf[..take]);
                    left -= take as u64;
                }
                if verify.read(&mut buf[..1])? != 0 {
                    return Err(MediaError::Corrupt);
                }
                let matched = sha.finalize().as_slice() == digest;
                drop(verify);
                drop(root);
                fs.unmount()?;
                matched
            };
            if !readback {
                return Err(MediaError::Corrupt);
            }
            staged.push(IsoStagedFile {
                path,
                bytes: length,
                sha256: hex::encode(digest),
                partition: if part_efi { "efi" } else { "payload" },
                independent_fat32_readback_verified: true,
            });
        }
        let mut tail = [0u8; 1];
        if input.read(&mut tail[..])? != 0 {
            return Err(MediaError::Corrupt);
        }
        let upper = seen
            .iter()
            .map(|x| x.to_ascii_uppercase())
            .collect::<std::collections::HashSet<_>>();
        if !["EFI/BOOT/BOOTX64.EFI", "SOURCES/BOOT.WIM", "SETUP.EXE"]
            .iter()
            .all(|s| upper.contains(*s))
            || (!with_verified_swm
                && (upper.contains("SOURCES/INSTALL.WIM") == upper.contains("SOURCES/INSTALL.ESD")))
        {
            return Err(MediaError::Corrupt);
        }
        if verify_gpt(&mut self.file, self.b)? != original_gpt {
            return Err(MediaError::Corrupt);
        }
        let proof = self.verify()?;
        Ok(IsoStreamReceipt {
            virtual_only: true,
            physical_write_authorized: false,
            windows_setup_boot_verified: false,
            installer_compatible_verified: false,
            full_disk_sha256_verified: false,
            source_iso_unchanged_verified: false,
            gpt_integrity_verified: proof.primary_and_backup_gpt_verified,
            efi_fat32_verified: proof.esp_fat32_verified,
            payload_fat32_verified: proof.payload_fat32_verified,
            staged_file_count: staged.len(),
            staged_bytes: total,
            files: staged,
        })
    }
    /// Stream a locally supplied, format-valid synthetic EFI file into the
    /// anonymous FAT32 ESP and independently read it back. Source unchanged,
    /// GPT intact, reserved payload still unformatted. No boot claim.
    pub fn stage_efi_test(
        &mut self,
        source: &std::path::Path,
    ) -> Result<LargeEfiReceipt, MediaError> {
        let original = read_source_efi(source)?;
        ensure_x64_efi_header(&original)?;
        let original_sha = hex::encode(Sha256::digest(&original));
        {
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
            let root = fs.root_dir();
            let efi = root.create_dir("EFI")?;
            let boot = efi.create_dir("BOOT")?;
            let mut output = boot.create_file("BOOTX64.EFI")?;
            let mut sha = Sha256::new();
            for chunk in original.chunks(64 * 1024) {
                output.write_all(chunk)?;
                sha.update(chunk);
            }
            output.flush()?;
            if hex::encode(sha.finalize()) != original_sha {
                return Err(MediaError::Corrupt);
            }
            drop(output);
            drop(boot);
            drop(efi);
            drop(root);
            fs.unmount()?;
        }
        self.file.sync_all()?;
        let copy_sha = {
            let view = Region {
                file: &mut self.file,
                base: self.b.esp_first * SECTOR,
                length: ESP_BYTES,
                pos: 0,
            };
            let fs = FileSystem::new(view, FsOptions::new())?;
            let root = fs.root_dir();
            let mut file = root.open_file("EFI/BOOT/BOOTX64.EFI")?;
            let mut hasher = Sha256::new();
            let mut bytes = 0u64;
            let mut buffer = [0u8; 65536];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                bytes += n as u64;
                if bytes > MAX_EFI_BYTES as u64 {
                    return Err(MediaError::Corrupt);
                }
                hasher.update(&buffer[..n]);
            }
            if bytes != original.len() as u64 {
                return Err(MediaError::Corrupt);
            }
            hex::encode(hasher.finalize())
        };
        let source_after = read_source_efi(source)?;
        if source_after != original || copy_sha != original_sha {
            return Err(MediaError::Corrupt);
        }
        let layout = self.verify()?;
        Ok(LargeEfiReceipt {
            layout,
            virtual_only: true,
            physical_write_authorized: false,
            windows_setup_boot_verified: false,
            efi_structure_verified: true,
            efi_executability_verified: false,
            efi_source_bytes: original.len() as u64,
            efi_source_sha256: original_sha,
            efi_fat32_readback_sha256: copy_sha,
            efi_source_unchanged: true,
        })
    }
    pub fn verify(&mut self) -> Result<LargePlan, MediaError> {
        let metadata_sha256 = verify_gpt(&mut self.file, self.b)?;
        // Explicitly check three bounded sentinel sectors, not the complete
        // reserved filesystem. This is not a full-disk integrity assertion.
        if !self.payload_fat32 {
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
        }
        if self.payload_fat32 {
            let view = Region {
                file: &mut self.file,
                base: self.b.data_first * SECTOR,
                length: (self.b.data_last - self.b.data_first + 1) * SECTOR,
                pos: 0,
            };
            let fs = FileSystem::new(view, FsOptions::new())?;
            if fs.fat_type() != FatType::Fat32 {
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
            payload_filesystem_formatted: self.payload_fat32,
            ntfs_writer_available: false,
            esp_fat32_verified: true,
            primary_and_backup_gpt_verified: true,
            reserved_payload_sampled_zero: !self.payload_fat32,
            payload_fat32_verified: self.payload_fat32,
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
    /// Explicit second FAT32 partition in an anonymous Linux-only disk.
    /// Not NTFS, no automatic installer compatibility or persistence.
    pub fn format_payload_fat32(&mut self) -> Result<LargePlan, MediaError> {
        if self.payload_fat32 {
            return Err(MediaError::Corrupt);
        }
        self.verify()?;
        {
            let region = Region {
                file: &mut self.file,
                base: self.b.data_first * SECTOR,
                length: (self.b.data_last - self.b.data_first + 1) * SECTOR,
                pos: 0,
            };
            fatfs::format_volume(
                region,
                FormatVolumeOptions::new()
                    .fat_type(FatType::Fat32)
                    .bytes_per_cluster(8192)
                    .volume_label(*b"BOOTNEXDATA"),
            )?;
        }
        self.file.sync_all()?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if self.file.metadata()?.blocks().saturating_mul(512) > 128 * 1024 * 1024 {
                return Err(MediaError::Capacity);
            }
        }
        self.payload_fat32 = true;
        self.verify()
    }
    /// Conservative point-in-time check on the same filesystem where the
    /// anonymous sparse disk is allocated. Linux is the only enabled target.
    fn admit_swm_storage(
        &self,
        total: u64,
        profile: SwmStageProfile,
    ) -> Result<(u64, u64), MediaError> {
        let payload_bytes = (self.b.data_last - self.b.data_first + 1)
            .checked_mul(SECTOR)
            .ok_or(MediaError::Capacity)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            // SAFETY: the fd belongs to a live regular tempfile; the kernel
            // initializes this local statvfs object only on successful return.
            let result = unsafe { libc::fstatvfs(self.file.as_raw_fd(), stats.as_mut_ptr()) };
            if result != 0 {
                return Err(MediaError::Capacity);
            }
            // SAFETY: fstatvfs returned success and fully populated stats.
            let stats = unsafe { stats.assume_init() };
            let available = stats.f_bavail.saturating_mul(stats.f_frsize);
            let required = swm_admission_requirement(total, payload_bytes, profile)?;
            if available < required {
                return Err(MediaError::Capacity);
            }
            Ok((available, required))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (total, payload_bytes, profile);
            Err(MediaError::Capacity)
        }
    }

    /// Stage an independently wimlib-verified split archive into the large
    /// anonymous FAT32 payload partition. Bounded, host-space-admitted demo;
    /// real multi-GiB Windows installers still require another qualification.
    pub fn stage_verified_swm_demo(
        &mut self,
        split_dir: &std::path::Path,
    ) -> Result<LargeSwmReceipt, MediaError> {
        self.stage_swm_with_profile(split_dir, SwmStageProfile::BoundedDemo)
    }

    /// An explicitly selected, developer-only, larger virtual staging path.
    /// Requires 8-24 GiB nominal capacity and enough free host bytes to
    /// satisfy the preflight. No path to a block device or disk export exists.
    pub fn stage_fullsize_swm_virtual(
        &mut self,
        split_dir: &std::path::Path,
    ) -> Result<LargeSwmReceipt, MediaError> {
        if self.b.disk < 8 * 1024 * 1024 * 1024 {
            return Err(MediaError::Capacity);
        }
        self.stage_swm_with_profile(split_dir, SwmStageProfile::FullSizeVirtual)
    }

    fn stage_swm_with_profile(
        &mut self,
        split_dir: &std::path::Path,
        profile: SwmStageProfile,
    ) -> Result<LargeSwmReceipt, MediaError> {
        const MIB: u64 = 1024 * 1024;
        let (max_part, max_aggregate, max_parts) = match profile {
            SwmStageProfile::BoundedDemo => (512 * MIB, 1024 * MIB, 16),
            SwmStageProfile::FullSizeVirtual => (u64::from(u32::MAX), 16 * 1024 * MIB, 64),
        };
        if !self.payload_fat32 {
            return Err(MediaError::Corrupt);
        }
        let parts = crate::swm_qualification::verify_existing_split(split_dir)
            .map_err(|_| MediaError::Corrupt)?;
        if !(2..=max_parts).contains(&parts.len()) {
            return Err(MediaError::Capacity);
        }
        let mut total = 0u64;
        for part in &parts {
            if part.bytes == 0 || part.bytes > max_part {
                return Err(MediaError::Capacity);
            }
            total = total.checked_add(part.bytes).ok_or(MediaError::Capacity)?;
            if total > max_aggregate {
                return Err(MediaError::Capacity);
            }
        }

        // Verify volume capacity and free bytes on the actual anonymous
        // tempfile filesystem. This is admission, not a reservation against
        // concurrent fills. Mid-transfer allocation errors fail closed.
        let (available_host, required_host) = self.admit_swm_storage(total, profile)?;

        // No payload may touch GPT metadata or the EFI partition. Only the
        // bounded Region below accepts writes, not the entire sparse file.
        let original_gpt = verify_gpt(&mut self.file, self.b)?;
        {
            let view = Region {
                file: &mut self.file,
                base: self.b.data_first * SECTOR,
                length: (self.b.data_last - self.b.data_first + 1) * SECTOR,
                pos: 0,
            };
            let fs = FileSystem::new(view, FsOptions::new())?;
            if fs.fat_type() != FatType::Fat32 {
                return Err(MediaError::Corrupt);
            }
            let root = fs.root_dir();
            // Reject any existing SOURCES directory, not only exact files.
            if root.open_dir("SOURCES").is_ok() {
                return Err(MediaError::Corrupt);
            }
            let sources = root.create_dir("SOURCES")?;
            for part in &parts {
                let source_path = split_dir.join(&part.filename);
                if !std::fs::symlink_metadata(&source_path)?
                    .file_type()
                    .is_file()
                {
                    return Err(MediaError::Corrupt);
                }
                let mut source = File::open(source_path)?;
                if source.metadata()?.len() != part.bytes {
                    return Err(MediaError::Corrupt);
                }
                let mut dest = sources.create_file(&part.filename)?;
                let mut sha = Sha256::new();
                let mut remaining = part.bytes;
                let mut buf = [0u8; 65_536];
                while remaining > 0 {
                    let take = remaining.min(buf.len() as u64) as usize;
                    source.read_exact(&mut buf[..take])?;
                    dest.write_all(&buf[..take])?;
                    sha.update(&buf[..take]);
                    remaining -= take as u64;
                }
                if source.read(&mut buf[..1])? != 0 || hex::encode(sha.finalize()) != part.sha256 {
                    return Err(MediaError::Corrupt);
                }
                dest.flush()?;
            }
            drop(sources);
            drop(root);
            fs.unmount()?;
        }
        self.file.sync_all()?;
        // Independent filesystem read-back, not just an in-memory copy hash.
        {
            let view = Region {
                file: &mut self.file,
                base: self.b.data_first * SECTOR,
                length: (self.b.data_last - self.b.data_first + 1) * SECTOR,
                pos: 0,
            };
            let fs = FileSystem::new(view, FsOptions::new())?;
            let root = fs.root_dir();
            let sources = root.open_dir("SOURCES")?;
            let mut found = 0usize;
            for entry in sources.iter() {
                let entry = entry?;
                if entry.file_name() == "." || entry.file_name() == ".." {
                    continue;
                }
                if !entry.is_file() {
                    return Err(MediaError::Corrupt);
                }
                found += 1;
            }
            if found != parts.len() {
                return Err(MediaError::Corrupt);
            }
            for part in &parts {
                let mut file = sources.open_file(&part.filename)?;
                let mut sha = Sha256::new();
                let mut remaining = part.bytes;
                let mut buf = [0u8; 65_536];
                while remaining > 0 {
                    let take = remaining.min(buf.len() as u64) as usize;
                    file.read_exact(&mut buf[..take])?;
                    sha.update(&buf[..take]);
                    remaining -= take as u64;
                }
                if file.read(&mut buf[..1])? != 0 || hex::encode(sha.finalize()) != part.sha256 {
                    return Err(MediaError::Corrupt);
                }
            }
        }
        // Detect source mutations during staging and verify archive structure
        // again. No disk or receipts survive on any normal error path.
        let after = crate::swm_qualification::verify_existing_split(split_dir)
            .map_err(|_| MediaError::Corrupt)?;
        if parts.len() != after.len()
            || parts.iter().zip(&after).any(|(a, b)| {
                a.filename != b.filename || a.bytes != b.bytes || a.sha256 != b.sha256
            })
            || verify_gpt(&mut self.file, self.b)? != original_gpt
        {
            return Err(MediaError::Corrupt);
        }
        let layout = self.verify()?;
        Ok(LargeSwmReceipt {
            virtual_only: true,
            physical_write_authorized: false,
            windows_setup_boot_verified: false,
            installer_compatible_verified: false,
            full_disk_sha256_verified: false,
            split_archive_preverified: true,
            payload_fat32_verified: layout.payload_fat32_verified,
            gpt_integrity_verified: layout.primary_and_backup_gpt_verified,
            disk_bytes: layout.disk_bytes,
            total_staged_bytes: total,
            available_host_bytes_at_admission: available_host,
            required_free_host_bytes_at_admission: required_host,
            host_storage_admission_passed: true,
            full_size_virtual_profile_requested: profile == SwmStageProfile::FullSizeVirtual,
            persistent_disk_image_produced: false,
            staged_parts: parts,
        })
    }

    /// Stream a single bounded synthetic file into the second FAT32 only,
    /// rehashing the source and independently reading the FAT32 file.
    pub fn stage_synthetic_payload(
        &mut self,
        source: &mut File,
        expected_sha256: &str,
    ) -> Result<PayloadStageReport, MediaError> {
        const MAX_BYTES: u64 = 32 * 1024 * 1024;
        if !self.payload_fat32
            || !source.metadata()?.is_file()
            || expected_sha256.len() != 64
            || !expected_sha256.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(MediaError::Corrupt);
        }
        let count = source.metadata()?.len();
        if count == 0 || count > MAX_BYTES {
            return Err(MediaError::Capacity);
        }
        fn fingerprint(source: &mut File, size: u64) -> Result<String, MediaError> {
            source.seek(SeekFrom::Start(0))?;
            let mut sha = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut left = size;
            while left > 0 {
                let n = left.min(buffer.len() as u64) as usize;
                source.read_exact(&mut buffer[..n])?;
                sha.update(&buffer[..n]);
                left -= n as u64;
            }
            if source.read(&mut buffer[..1])? != 0 {
                return Err(MediaError::Corrupt);
            }
            Ok(hex::encode(sha.finalize()))
        }
        let before = fingerprint(source, count)?;
        if before != expected_sha256.to_ascii_lowercase() {
            return Err(MediaError::Corrupt);
        }
        let initial_gpt = verify_gpt(&mut self.file, self.b)?;
        source.seek(SeekFrom::Start(0))?;
        let copied = {
            let region = Region {
                file: &mut self.file,
                base: self.b.data_first * SECTOR,
                length: (self.b.data_last - self.b.data_first + 1) * SECTOR,
                pos: 0,
            };
            let fs = FileSystem::new(region, FsOptions::new())?;
            if fs.fat_type() != FatType::Fat32 {
                return Err(MediaError::Corrupt);
            }
            let root = fs.root_dir();
            // Never overwrite an existing file in this virtual session.
            if root.open_file("SOURCES/PAYLOAD.BIN").is_ok() {
                return Err(MediaError::Corrupt);
            }
            root.create_dir("SOURCES")?;
            let mut dest = root.create_file("SOURCES/PAYLOAD.BIN")?;
            let mut buf = [0u8; 65536];
            let mut left = count;
            let mut sha = Sha256::new();
            while left > 0 {
                let n = left.min(buf.len() as u64) as usize;
                source.read_exact(&mut buf[..n])?;
                dest.write_all(&buf[..n])?;
                sha.update(&buf[..n]);
                left -= n as u64;
            }
            if source.read(&mut buf[..1])? != 0 {
                return Err(MediaError::Corrupt);
            }
            dest.flush()?;
            drop(dest);
            drop(root);
            fs.unmount()?;
            hex::encode(sha.finalize())
        };
        if copied != before {
            return Err(MediaError::Corrupt);
        }
        self.file.sync_all()?;
        let after = fingerprint(source, count)?;
        if after != before {
            return Err(MediaError::Corrupt);
        }
        let readback = {
            let region = Region {
                file: &mut self.file,
                base: self.b.data_first * SECTOR,
                length: (self.b.data_last - self.b.data_first + 1) * SECTOR,
                pos: 0,
            };
            let fs = FileSystem::new(region, FsOptions::new())?;
            let root = fs.root_dir();
            let mut file = root.open_file("SOURCES/PAYLOAD.BIN")?;
            let mut sha = Sha256::new();
            let mut left = count;
            let mut buf = [0u8; 65536];
            while left > 0 {
                let n = left.min(buf.len() as u64) as usize;
                file.read_exact(&mut buf[..n])?;
                sha.update(&buf[..n]);
                left -= n as u64;
            }
            if file.read(&mut buf[..1])? != 0 {
                return Err(MediaError::Corrupt);
            }
            hex::encode(sha.finalize())
        };
        if readback != before || verify_gpt(&mut self.file, self.b)? != initial_gpt {
            return Err(MediaError::Corrupt);
        }
        let proof = self.verify()?;
        Ok(PayloadStageReport {
            virtual_only: true,
            physical_write_authorized: false,
            windows_setup_boot_verified: false,
            installer_compatible_verified: false,
            full_disk_sha256_verified: false,
            payload_fat32_verified: proof.payload_fat32_verified,
            source_bytes: count,
            source_sha256: before.clone(),
            fat32_readback_sha256: readback,
            source_after_sha256: after,
            staged_path: "SOURCES/PAYLOAD.BIN",
            primary_and_backup_gpt_verified: proof.primary_and_backup_gpt_verified,
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
    #[test]
    fn larger_swm_host_and_partition_admission_fails_closed() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(
            swm_admission_requirement(288 * MIB, 1024 * MIB, SwmStageProfile::BoundedDemo).unwrap(),
            832 * MIB
        );
        assert_eq!(
            swm_admission_requirement(MIB, 1024 * MIB, SwmStageProfile::BoundedDemo).unwrap(),
            512 * MIB
        );
        for invalid in [0, 1024 * MIB + 1, u64::MAX] {
            assert!(
                swm_admission_requirement(invalid, 4 * 1024 * MIB, SwmStageProfile::BoundedDemo)
                    .is_err()
            );
        }
        assert!(
            swm_admission_requirement(600 * MIB, 700 * MIB, SwmStageProfile::BoundedDemo).is_err()
        );
        assert!(
            swm_admission_requirement(500 * MIB, 800 * MIB, SwmStageProfile::BoundedDemo).is_ok()
        );
        assert!(
            swm_admission_requirement(500 * MIB, 600 * MIB, SwmStageProfile::BoundedDemo).is_err()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn combined_mode_rejects_legacy_magic_and_reserved_install_sources() {
        let mut disk = LargeSparseDisk::new(1).unwrap();
        disk.format_payload_fat32().unwrap();
        let mut legacy = std::io::Cursor::new(b"BNXI0001".to_vec());
        assert!(disk.stage_iso_stream_mode(&mut legacy, true).is_err());
        for forbidden in [
            "SOURCES/install.wim",
            "SOURCES/install.esd",
            "sources/install.swm",
            "SoUrCeS/InStAlL2.SwM",
        ] {
            let name = forbidden.as_bytes();
            let mut data = b"BNXI0002".to_vec();
            data.extend_from_slice(&4u16.to_le_bytes());
            data.extend_from_slice(&(name.len() as u16).to_le_bytes());
            data.extend_from_slice(name);
            let mut input = std::io::Cursor::new(data);
            assert!(
                disk.stage_iso_stream_mode(&mut input, true).is_err(),
                "{forbidden}"
            );
        }
    }
    #[test]
    fn fullsize_swm_policy_handles_over_4gib_without_host_allocation() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let require =
            swm_admission_requirement(5 * GIB, 12 * GIB, SwmStageProfile::FullSizeVirtual).unwrap();
        assert_eq!(require, 11 * GIB);
        assert!(
            swm_admission_requirement(5 * GIB, 6 * GIB, SwmStageProfile::FullSizeVirtual,).is_err()
        );
        assert!(
            swm_admission_requirement(5 * GIB, 12 * GIB, SwmStageProfile::BoundedDemo,).is_err()
        );
        for invalid in [0, 16 * GIB + 1, u64::MAX] {
            assert!(
                swm_admission_requirement(invalid, 24 * GIB, SwmStageProfile::FullSizeVirtual,)
                    .is_err()
            );
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn optional_second_fat32_and_independent_payload_sha_roundtrip() {
        let mut disk = LargeSparseDisk::new(1).unwrap();
        let before = disk.verify().unwrap().metadata_sha256;
        assert!(!disk.verify().unwrap().payload_filesystem_formatted);
        assert!(
            disk.stage_synthetic_payload(&mut tempfile::tempfile().unwrap(), &"0".repeat(64))
                .is_err()
        );
        let formatted = disk.format_payload_fat32().unwrap();
        assert!(formatted.payload_fat32_verified && formatted.payload_filesystem_formatted);
        assert!(!formatted.windows_installer_compatible && !formatted.windows_setup_boot_verified);
        assert!(!formatted.reserved_payload_sampled_zero);
        assert_eq!(before, formatted.metadata_sha256);
        assert!(disk.format_payload_fat32().is_err());
        let mut file = tempfile::tempfile().unwrap();
        let data = (0..500_000u32)
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>();
        file.write_all(&data).unwrap();
        let sha = hex::encode(Sha256::digest(&data));
        assert!(
            disk.stage_synthetic_payload(&mut file, &"f".repeat(64))
                .is_err()
        );
        let report = disk.stage_synthetic_payload(&mut file, &sha).unwrap();
        assert_eq!(report.source_sha256, sha);
        assert_eq!(report.fat32_readback_sha256, sha);
        assert_eq!(report.source_after_sha256, sha);
        assert_eq!(report.source_bytes, data.len() as u64);
        assert!(report.payload_fat32_verified && report.primary_and_backup_gpt_verified);
        assert!(!report.windows_setup_boot_verified && !report.physical_write_authorized);
        assert!(disk.stage_synthetic_payload(&mut file, &sha).is_err());
        assert_eq!(disk.verify().unwrap().metadata_sha256, before);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn optional_second_fat32_on_eight_gib_stays_sparse() {
        let mut disk = LargeSparseDisk::new(8).unwrap();
        let p = disk.format_payload_fat32().unwrap();
        assert!(p.payload_fat32_verified && p.esp_fat32_verified);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(disk.file.metadata().unwrap().blocks() * 512 < 128 * 1024 * 1024);
        }
    }
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
