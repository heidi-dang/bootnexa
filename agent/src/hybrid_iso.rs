//! Strict, read-only GPT/ISO hybrid qualification for anonymous virtual copying.
//! NOT a general Linux ISO parser. Only small dual-format GPT/FAT32 images with
//! equivalent x64 EFI payloads in both ISO9660 and ESP are eligible.
//! No OS disk/USB APIs or privileged helper calls exist in this module.
use crate::{
    iso_inspect::{IsoError, inspect},
    iso_tree::{TreeError, enumerate},
    partition_layout::{MediaError, Scheme, plan, verify_partition_table},
    virtual_boot_media::read_efi_payload,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
use thiserror::Error;

const CHUNK: usize = 64 * 1024;
const MAX_SIZE: u64 = 256 * 1024 * 1024;
#[derive(Debug, Error)]
pub enum HybridError {
    #[error("unsupported or unsafe hybrid ISO structure")]
    Unsupported,
    #[error("file content, partition or full-image verification mismatch")]
    Verification,
    #[error("ISO descriptor: {0}")]
    Iso(#[from] IsoError),
    #[error("ISO directory: {0}")]
    Tree(#[from] TreeError),
    #[error("GPT/ESP: {0}")]
    Media(#[from] MediaError),
    #[error("virtual-only file I/O: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridReport {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub linux_distribution_boot_verified: bool,
    pub windows_setup_verified: bool,
    pub boot_execution_verified: bool,
    pub iso9660_verified: bool,
    pub gpt_primary_backup_verified: bool,
    pub fat32_efi_verified: bool,
    pub iso_esp_efi_match: bool,
    pub source_bytes: u64,
    pub source_sha256: String,
    pub virtual_readback_sha256: String,
}
pub struct VirtualHybrid {
    image: File,
    report: HybridReport,
}
fn sha<R: Read + Seek>(file: &mut R) -> Result<String, std::io::Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = [0u8; CHUNK];
    let mut hash = Sha256::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hex::encode(hash.finalize()))
}
fn qualify(file: &mut File, length: u64) -> Result<(), HybridError> {
    if !(80 * 1024 * 1024..=MAX_SIZE).contains(&length)
        || !length.is_multiple_of(512)
        || !file.metadata()?.is_file()
    {
        return Err(HybridError::Unsupported);
    }
    let info = inspect(file, length)?;
    if !info.iso9660 || !info.hybrid_mbr_candidate || !info.el_torito || !info.uefi_catalog_entry {
        return Err(HybridError::Unsupported);
    }
    let layout = plan(length, Scheme::Gpt)?;
    verify_partition_table(file, &layout)?;
    let iso_tree = enumerate(file, length)?;
    let iso_efi = iso_tree
        .files
        .iter()
        .find(|f| f.path == "EFI/BOOT/BOOTX64.EFI")
        .ok_or(HybridError::Unsupported)?;
    if iso_efi.length < 256 || iso_efi.length > 8 * 1024 * 1024 {
        return Err(HybridError::Unsupported);
    }
    let mut original = vec![0u8; iso_efi.length as usize];
    file.seek(SeekFrom::Start(iso_efi.offset))?;
    file.read_exact(&mut original)?;
    let esp_payload = read_efi_payload(file, &layout)?;
    if original != esp_payload {
        return Err(HybridError::Verification);
    }
    Ok(())
}
impl VirtualHybrid {
    pub fn from_iso_file(source: &mut File) -> Result<Self, HybridError> {
        let size = source.metadata()?.len();
        qualify(source, size)?;
        let before = sha(source)?;
        source.seek(SeekFrom::Start(0))?;
        let mut image = tempfile::tempfile()?;
        let mut left = size;
        let mut buffer = [0u8; CHUNK];
        let mut write_sha = Sha256::new();
        while left > 0 {
            let count = left.min(CHUNK as u64) as usize;
            source.read_exact(&mut buffer[..count])?;
            image.write_all(&buffer[..count])?;
            write_sha.update(&buffer[..count]);
            left -= count as u64;
        }
        image.sync_all()?;
        let after = sha(source)?;
        let copied = hex::encode(write_sha.finalize());
        let readback = sha(&mut image)?;
        if before != after
            || before != copied
            || copied != readback
            || image.metadata()?.len() != size
        {
            return Err(HybridError::Verification);
        }
        qualify(&mut image, size)?;
        Ok(Self {
            image,
            report: HybridReport {
                virtual_only: true,
                physical_write_authorized: false,
                linux_distribution_boot_verified: false,
                windows_setup_verified: false,
                boot_execution_verified: false,
                iso9660_verified: true,
                gpt_primary_backup_verified: true,
                fat32_efi_verified: true,
                iso_esp_efi_match: true,
                source_bytes: size,
                source_sha256: before,
                virtual_readback_sha256: readback,
            },
        })
    }
    pub fn report(&self) -> &HybridReport {
        &self.report
    }
    pub fn export_to_regular_file(&mut self, dst: &mut File) -> Result<String, HybridError> {
        if !dst.metadata()?.is_file() || dst.metadata()?.len() != 0 {
            return Err(HybridError::Unsupported);
        }
        self.image.seek(SeekFrom::Start(0))?;
        let mut left = self.report.source_bytes;
        let mut buf = [0u8; CHUNK];
        while left > 0 {
            let count = left.min(CHUNK as u64) as usize;
            self.image.read_exact(&mut buf[..count])?;
            dst.write_all(&buf[..count])?;
            left -= count as u64;
        }
        dst.sync_all()?;
        let digest = sha(dst)?;
        if digest != self.report.source_sha256 || dst.metadata()?.len() != self.report.source_bytes
        {
            return Err(HybridError::Verification);
        }
        Ok(digest)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_iso_is_not_a_gpt_hybrid() {
        let mut regular = tempfile::tempfile().unwrap();
        regular.set_len(96 * 1024 * 1024).unwrap();
        assert!(VirtualHybrid::from_iso_file(&mut regular).is_err());
    }
    #[test]
    fn non_file_source_is_never_supported() {
        let mut empty = tempfile::tempfile().unwrap();
        assert!(VirtualHybrid::from_iso_file(&mut empty).is_err());
    }
}
