//! Anonymous FAT32 EFI System Partition builder, backed by a regular file.
//! This type never accepts OS device names, paths, or raw block handles.
use crate::partition_layout::{
    Layout, MediaError, SECTOR, Scheme, plan, verify_partition_table, write_partition_table,
};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

const MAX_PAYLOAD: usize = 8 * 1024 * 1024;
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualBootReport {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub scheme: String,
    pub disk_bytes: u64,
    pub partition_start_lba: u64,
    pub partition_bytes: u64,
    pub payload_path: String,
    pub payload_sha256: String,
    pub readback_sha256: String,
    pub payload_verified_bytes: usize,
    pub full_partition_table_verified: bool,
    pub fat32_verified: bool,
    pub boot_execution_verified: bool,
}
struct PartitionView<'a> {
    file: &'a mut File,
    start: u64,
    len: u64,
    pos: u64,
}
impl<'a> PartitionView<'a> {
    fn new(file: &'a mut File, layout: &Layout) -> Self {
        Self {
            file,
            start: layout.first_lba * SECTOR,
            len: layout.partition_bytes,
            pos: 0,
        }
    }
    fn seek_absolute(&mut self, pos: u64) -> io::Result<u64> {
        if pos > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "partition boundary exceeded",
            ));
        }
        self.pos = pos;
        Ok(pos)
    }
}
impl Read for PartitionView<'_> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let count = (self.len - self.pos).min(data.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(self.start + self.pos))?;
        let read = self.file.read(&mut data[..count])?;
        self.pos += read as u64;
        Ok(read)
    }
}
impl Write for PartitionView<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let count = (self.len - self.pos).min(data.len() as u64) as usize;
        if count == 0 && !data.is_empty() {
            return Err(io::Error::other("partition write exceeded bounds"));
        }
        self.file.seek(SeekFrom::Start(self.start + self.pos))?;
        let written = self.file.write(&data[..count])?;
        self.pos += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for PartitionView<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(x) => i128::from(x),
            SeekFrom::Current(x) => i128::from(self.pos) + i128::from(x),
            SeekFrom::End(x) => i128::from(self.len) + i128::from(x),
        };
        if next < 0 || next > i128::from(self.len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "partition seek outside virtual boundary",
            ));
        }
        self.seek_absolute(next as u64)
    }
}
/// Not clonable and holds no OS path; only a newly created anonymous tempfile.
pub struct VirtualBootMedia {
    file: File,
    layout: Layout,
}
impl VirtualBootMedia {
    pub fn new(size: u64, scheme: Scheme) -> Result<Self, MediaError> {
        let layout = plan(size, scheme)?;
        let mut file = tempfile::tempfile()?;
        file.set_len(size)?;
        write_partition_table(&mut file, &layout)?;
        let view = PartitionView::new(&mut file, &layout);
        fatfs::format_volume(
            view,
            FormatVolumeOptions::new()
                .fat_type(FatType::Fat32)
                .bytes_per_cluster(512)
                .volume_label(*b"BOOTNEXA   "),
        )?;
        file.sync_all()?;
        Ok(Self { file, layout })
    }
    pub fn layout(&self) -> &Layout {
        &self.layout
    }
    pub fn add_efi_application(&mut self, bytes: &[u8]) -> Result<VirtualBootReport, MediaError> {
        if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
            return Err(MediaError::Capacity);
        }
        // Structural PE/COFF UEFI application qualification, NOT boot execution.
        if bytes.len() < 0x100 || &bytes[..2] != b"MZ" {
            return Err(MediaError::Corrupt);
        }
        let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        if pe_offset
            .checked_add(0x60)
            .is_none_or(|end| end > bytes.len())
            || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0"
            || bytes[pe_offset + 4..pe_offset + 6] != [0x64, 0x86]
            || bytes[pe_offset + 24..pe_offset + 26] != [0x0b, 0x02]
            || bytes[pe_offset + 24 + 68..pe_offset + 24 + 70] != [10, 0]
        {
            return Err(MediaError::Corrupt);
        }
        let expected = hex::encode(Sha256::digest(bytes));
        {
            let view = PartitionView::new(&mut self.file, &self.layout);
            let fs = FileSystem::new(view, FsOptions::new())?;
            let root = fs.root_dir();
            root.create_dir("EFI")?.create_dir("BOOT")?;
            let mut boot = root.create_file("EFI/BOOT/BOOTX64.EFI")?;
            boot.write_all(bytes)?;
            boot.flush()?;
            drop(boot);
            drop(root);
            fs.unmount()?;
        }
        self.file.sync_all()?;
        verify_partition_table(&mut self.file, &self.layout)?;
        let readback = self.read_efi_application()?;
        let actual = hex::encode(Sha256::digest(&readback));
        if actual != expected || bytes != readback {
            return Err(MediaError::Corrupt);
        }
        Ok(VirtualBootReport {
            virtual_only: true,
            physical_write_authorized: false,
            scheme: format!("{:?}", self.layout.scheme),
            disk_bytes: self.layout.total_lba * SECTOR,
            partition_start_lba: self.layout.first_lba,
            partition_bytes: self.layout.partition_bytes,
            payload_path: "EFI/BOOT/BOOTX64.EFI".into(),
            payload_sha256: expected,
            readback_sha256: actual,
            payload_verified_bytes: readback.len(),
            full_partition_table_verified: true,
            fat32_verified: true,
            boot_execution_verified: false,
        })
    }
    pub fn read_efi_application(&mut self) -> Result<Vec<u8>, MediaError> {
        let view = PartitionView::new(&mut self.file, &self.layout);
        let fs = FileSystem::new(view, FsOptions::new())?;
        if fs.fat_type() != FatType::Fat32 {
            return Err(MediaError::Corrupt);
        }
        let root = fs.root_dir();
        let file = root.open_file("EFI/BOOT/BOOTX64.EFI")?;
        let mut output = vec![];
        file.take(MAX_PAYLOAD as u64 + 1).read_to_end(&mut output)?;
        if output.len() > MAX_PAYLOAD {
            return Err(MediaError::Corrupt);
        }
        Ok(output)
    }
    pub fn verify(&mut self) -> Result<(), MediaError> {
        verify_partition_table(&mut self.file, &self.layout)?;
        let view = PartitionView::new(&mut self.file, &self.layout);
        let fs = FileSystem::new(view, FsOptions::new())?;
        if fs.fat_type() != FatType::Fat32 {
            return Err(MediaError::Corrupt);
        }
        Ok(())
    }
    /// Explicit export for developer-only virtual media. Caller must provide an
    /// already-created regular-file handle; this module never opens a disk path.
    pub fn export_to_regular_file(&mut self, destination: &mut File) -> Result<String, MediaError> {
        if !destination.metadata()?.is_file() || destination.metadata()?.len() != 0 {
            return Err(MediaError::Corrupt);
        }
        self.verify()?;
        self.file.rewind()?;
        let mut sha = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut copied = 0u64;
        while copied < self.layout.total_lba * SECTOR {
            let amount = (self.layout.total_lba * SECTOR - copied).min(buf.len() as u64) as usize;
            self.file.read_exact(&mut buf[..amount])?;
            destination.write_all(&buf[..amount])?;
            sha.update(&buf[..amount]);
            copied += amount as u64;
        }
        destination.sync_all()?;
        destination.rewind()?;
        let mut actual = Sha256::new();
        loop {
            let n = destination.read(&mut buf)?;
            if n == 0 {
                break;
            }
            actual.update(&buf[..n]);
        }
        let expected = sha.finalize();
        if actual.finalize().as_slice() != expected.as_slice() {
            return Err(MediaError::Corrupt);
        }
        Ok(hex::encode(expected))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fake_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 4096];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0x98 + 68..0x98 + 70].copy_from_slice(&10u16.to_le_bytes());
        bytes
    }
    #[test]
    fn virtual_gpt_and_mbr_fat32_efi_roundtrip() {
        for scheme in [Scheme::Gpt, Scheme::Mbr] {
            let mut disk = VirtualBootMedia::new(96 * 1024 * 1024, scheme).unwrap();
            let report = disk.add_efi_application(&fake_pe()).unwrap();
            assert_eq!(report.payload_sha256, report.readback_sha256);
            assert!(report.fat32_verified && report.full_partition_table_verified);
            assert!(!report.boot_execution_verified && !report.physical_write_authorized);
            disk.verify().unwrap();
            let mut exported = tempfile::tempfile().unwrap();
            let hash = disk.export_to_regular_file(&mut exported).unwrap();
            assert_eq!(hash.len(), 64);
            assert_eq!(exported.metadata().unwrap().len(), 96 * 1024 * 1024);
        }
    }
    #[test]
    fn payload_pe_validation_is_fail_closed() {
        let mut disk = VirtualBootMedia::new(96 * 1024 * 1024, Scheme::Gpt).unwrap();
        for case in [&[1u8, 2, 3][..], &[0u8; 256][..]] {
            assert!(disk.add_efi_application(case).is_err());
        }
        let mut wrong = fake_pe();
        wrong[0x98 + 68] = 2;
        assert!(disk.add_efi_application(&wrong).is_err());
    }
    #[test]
    fn partition_view_enforces_bounds() {
        let mut disk = VirtualBootMedia::new(96 * 1024 * 1024, Scheme::Gpt).unwrap();
        let mut view = PartitionView::new(&mut disk.file, &disk.layout);
        assert!(
            view.seek(SeekFrom::Start(disk.layout.partition_bytes + 1))
                .is_err()
        );
        view.seek(SeekFrom::End(-1)).unwrap();
        assert_eq!(view.write(&[1, 2]).unwrap(), 1);
        assert!(view.write(&[3]).is_err());
    }
}
