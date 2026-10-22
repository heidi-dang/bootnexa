//! A *single-version pinned* official Alpine virt ISO virtual-file qualification.
//! Not a general Linux installer engine. Never opens or writes any physical disk.
use crate::iso_inspect::{IsoError, inspect};
use fatfs::{FileSystem, FsOptions};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
use thiserror::Error;

pub const VERIFIED_ALPINE_VERSION: &str = "alpine-virt-3.24.2-x86_64";
pub const VERIFIED_SHA256: &str =
    "3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b";
const VERIFIED_SIZE: u64 = 69_206_016;
const MAX_EFI: u64 = 8 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum LinuxIsoError {
    #[error(
        "only the checksum-pinned official Alpine Linux 3.24.2 virtual ISO is currently eligible"
    )]
    Unsupported,
    #[error("official ISO or copied virtual-image digest mismatch")]
    Verification,
    #[error("invalid MBR EFI partition or missing UEFI fallback application")]
    Layout,
    #[error("ISO boot catalog inspection: {0}")]
    Iso(#[from] IsoError),
    #[error("regular-file I/O: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxIsoReport {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub distro_profile: String,
    pub linux_distribution_boot_verified: bool,
    pub boot_execution_verified: bool,
    pub publisher_sha256_matched: bool,
    pub mbr_efi_partition_verified: bool,
    pub fat_efi_bootloader_verified: bool,
    pub image_bytes: u64,
    pub source_sha256: String,
    pub copied_sha256: String,
    pub esp_offset: u64,
    pub esp_bytes: u64,
}
struct ReadOnlyPartition<'a> {
    file: &'a mut File,
    offset: u64,
    len: u64,
    pos: u64,
}
impl Read for ReadOnlyPartition<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = (self.len - self.pos).min(buf.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(self.offset + self.pos))?;
        let n = self.file.read(&mut buf[..size])?;
        self.pos += n as u64;
        Ok(n)
    }
}
impl Write for ReadOnlyPartition<'_> {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "read-only FAT boot qualification",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Seek for ReadOnlyPartition<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let pos = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.pos) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.len) + i128::from(n),
        };
        if pos < 0 || pos > i128::from(self.len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "EFI partition boundary exceeded",
            ));
        }
        self.pos = pos as u64;
        Ok(self.pos)
    }
}
fn hash(file: &mut File) -> Result<String, std::io::Error> {
    file.rewind()?;
    let mut sha = Sha256::new();
    let mut buf = [0u8; CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    Ok(hex::encode(sha.finalize()))
}
fn qualify(file: &mut File) -> Result<(u64, u64), LinuxIsoError> {
    if !file.metadata()?.is_file() || file.metadata()?.len() != VERIFIED_SIZE {
        return Err(LinuxIsoError::Unsupported);
    }
    let iso = inspect(file, VERIFIED_SIZE)?;
    if !iso.iso9660 || !iso.hybrid_mbr_candidate || !iso.el_torito || !iso.uefi_catalog_entry {
        return Err(LinuxIsoError::Layout);
    }
    let mut mbr = [0u8; 512];
    file.rewind()?;
    file.read_exact(&mut mbr)?;
    if mbr[510..512] != [0x55, 0xaa] {
        return Err(LinuxIsoError::Layout);
    }
    let mut esp = None;
    for entry in mbr[446..510].as_chunks::<16>().0 {
        let kind = entry[4];
        if kind == 0 {
            continue;
        }
        if kind != 0xef || (entry[0] != 0 && entry[0] != 0x80) || esp.is_some() {
            return Err(LinuxIsoError::Layout);
        }
        let start = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
        let sectors = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as u64;
        let offset = start.checked_mul(512).ok_or(LinuxIsoError::Layout)?;
        let bytes = sectors.checked_mul(512).ok_or(LinuxIsoError::Layout)?;
        if start == 0
            || bytes < 512 * 64
            || offset.checked_add(bytes).is_none_or(|n| n > VERIFIED_SIZE)
        {
            return Err(LinuxIsoError::Layout);
        }
        esp = Some((offset, bytes));
    }
    let (offset, len) = esp.ok_or(LinuxIsoError::Layout)?;
    let view = ReadOnlyPartition {
        file,
        offset,
        len,
        pos: 0,
    };
    let fs = FileSystem::new(view, FsOptions::new()).map_err(|_| LinuxIsoError::Layout)?;
    let root = fs.root_dir();
    let boot = root
        .open_file("EFI/BOOT/BOOTX64.EFI")
        .map_err(|_| LinuxIsoError::Layout)?;
    let mut app = vec![];
    boot.take(MAX_EFI + 1).read_to_end(&mut app)?;
    if app.len() < 256 || app.len() as u64 > MAX_EFI || &app[..2] != b"MZ" {
        return Err(LinuxIsoError::Layout);
    }
    let pe = u32::from_le_bytes(app[0x3c..0x40].try_into().unwrap()) as usize;
    if pe.checked_add(0x60).is_none_or(|n| n > app.len())
        || &app[pe..pe + 4] != b"PE\0\0"
        || app[pe + 4..pe + 6] != [0x64, 0x86]
        || app[pe + 24..pe + 26] != [0x0b, 0x02]
        || app[pe + 24 + 68..pe + 24 + 70] != [10, 0]
    {
        return Err(LinuxIsoError::Layout);
    }
    Ok((offset, len))
}
pub struct VerifiedAlpineVirtual {
    file: File,
    report: LinuxIsoReport,
}
impl VerifiedAlpineVirtual {
    pub fn from_verified_iso(src: &mut File) -> Result<Self, LinuxIsoError> {
        if !src.metadata()?.is_file() || src.metadata()?.len() != VERIFIED_SIZE {
            return Err(LinuxIsoError::Unsupported);
        }
        let source_hash = hash(src)?;
        if source_hash != VERIFIED_SHA256 {
            return Err(LinuxIsoError::Verification);
        }
        let (offset, len) = qualify(src)?;
        src.rewind()?;
        let mut file = tempfile::tempfile()?;
        let mut left = VERIFIED_SIZE;
        let mut buf = [0u8; CHUNK];
        let mut sha = Sha256::new();
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            src.read_exact(&mut buf[..n])?;
            file.write_all(&buf[..n])?;
            sha.update(&buf[..n]);
            left -= n as u64;
        }
        file.sync_all()?;
        let copy_hash = hex::encode(sha.finalize());
        if copy_hash != source_hash || hash(src)? != source_hash || hash(&mut file)? != copy_hash {
            return Err(LinuxIsoError::Verification);
        }
        let (copy_offset, copy_len) = qualify(&mut file)?;
        if (copy_offset, copy_len) != (offset, len) {
            return Err(LinuxIsoError::Verification);
        }
        Ok(Self {
            file,
            report: LinuxIsoReport {
                virtual_only: true,
                physical_write_authorized: false,
                distro_profile: VERIFIED_ALPINE_VERSION.into(),
                linux_distribution_boot_verified: false,
                boot_execution_verified: false,
                publisher_sha256_matched: true,
                mbr_efi_partition_verified: true,
                fat_efi_bootloader_verified: true,
                image_bytes: VERIFIED_SIZE,
                source_sha256: source_hash,
                copied_sha256: copy_hash,
                esp_offset: offset,
                esp_bytes: len,
            },
        })
    }
    pub fn report(&self) -> &LinuxIsoReport {
        &self.report
    }
    pub fn export_to_regular_file(&mut self, dst: &mut File) -> Result<String, LinuxIsoError> {
        if !dst.metadata()?.is_file() || dst.metadata()?.len() != 0 {
            return Err(LinuxIsoError::Unsupported);
        }
        self.file.rewind()?;
        let mut left = VERIFIED_SIZE;
        let mut buf = [0u8; CHUNK];
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            self.file.read_exact(&mut buf[..n])?;
            dst.write_all(&buf[..n])?;
            left -= n as u64;
        }
        dst.sync_all()?;
        let output_hash = hash(dst)?;
        if output_hash != self.report.source_sha256 || dst.metadata()?.len() != VERIFIED_SIZE {
            return Err(LinuxIsoError::Verification);
        }
        Ok(output_hash)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_other_images_before_any_export() {
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(VERIFIED_SIZE).unwrap();
        assert!(VerifiedAlpineVirtual::from_verified_iso(&mut file).is_err());
        assert!(!VERIFIED_SHA256.is_empty());
    }
    #[test]
    fn partition_view_rejects_writes_and_oob_seeks() {
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(4096).unwrap();
        let mut view = ReadOnlyPartition {
            file: &mut file,
            offset: 512,
            len: 1024,
            pos: 0,
        };
        assert!(view.write(&[1]).is_err());
        assert!(view.seek(SeekFrom::Start(1025)).is_err());
        view.seek(SeekFrom::End(-1)).unwrap();
        assert_eq!(view.read(&mut [0u8; 4]).unwrap(), 1);
    }
}
