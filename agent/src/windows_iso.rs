//! Windows installer ISO *candidate* preflight and byte-exact virtual CD-ROM staging.
//! Not a Windows Setup boot test, WIM extraction, FAT32 writer or physical USB path.
//! ISO9660 primary tree only: UDF/Joliet-only and multi-extent images fail closed.
use crate::{
    iso_inspect,
    iso_tree::{self, IsoFile},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use thiserror::Error;

const CHUNK: usize = 64 * 1024;
const WIM_HEADER_BYTES: usize = 208;
const MAX_BOOT_IMAGE: u64 = 128 * 1024 * 1024 * 1024;
const FAT32_FILE_MAX: u64 = (1u64 << 32) - 1;

#[derive(Debug, Error)]
pub enum WindowsIsoError {
    #[error("unsupported Windows installation ISO structure: {0}")]
    Unsupported(&'static str),
    #[error("corrupted WIM/ESD header or untrusted EFI loader")]
    Corrupt,
    #[error("ISO metadata rejected: {0}")]
    Tree(#[from] iso_tree::TreeError),
    #[error("ISO descriptor rejected: {0}")]
    Iso(#[from] iso_inspect::IsoError),
    #[error("read-only Windows ISO I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("source changed or virtual copy did not pass complete SHA-256 readback")]
    Verification,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WimHeader {
    pub image_count: u32,
    pub format_version: u32,
    pub part_number: u16,
    pub total_parts: u16,
    pub file_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsIsoReport {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub windows_setup_boot_verified: bool,
    pub windows_version_verified: bool,
    pub image_bytes: u64,
    pub scanned_files: usize,
    pub observed_file_bytes: u64,
    pub source_filesystem: &'static str,
    pub udf_translation_supported: bool,
    pub udf_signature_observed: bool,
    pub el_torito_uefi_catalog: bool,
    pub x64_efi_loader_header_valid: bool,
    pub setup_exe_observed: bool,
    pub boot_wim: Option<WimHeader>,
    pub install_wim: Option<WimHeader>,
    pub install_esd: Option<WimHeader>,
    pub installation_index_verified: bool,
    pub wim_split_implemented: bool,
    pub fat32_install_payload_compatible: Option<bool>,
    pub virtual_cdrom_staging_eligible: bool,
    pub recommended_handling: &'static str,
}

fn at<R: Read + Seek>(file: &mut R, offset: u64, bytes: &mut [u8]) -> Result<(), WindowsIsoError> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(bytes)?;
    Ok(())
}

fn parse_wim<R: Read + Seek>(file: &mut R, entry: &IsoFile) -> Result<WimHeader, WindowsIsoError> {
    if entry.length < WIM_HEADER_BYTES as u64 {
        return Err(WindowsIsoError::Corrupt);
    }
    let mut header = [0u8; WIM_HEADER_BYTES];
    at(file, entry.offset, &mut header)?;
    if &header[0..8] != b"MSWIM\0\0\0" {
        return Err(WindowsIsoError::Corrupt);
    }
    let header_bytes = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let format_version = u32::from_le_bytes(header[12..16].try_into().unwrap());
    let part_number = u16::from_le_bytes(header[40..42].try_into().unwrap());
    let total_parts = u16::from_le_bytes(header[42..44].try_into().unwrap());
    let image_count = u32::from_le_bytes(header[44..48].try_into().unwrap());
    if !(204..=4096).contains(&header_bytes)
        || header_bytes as u64 > entry.length
        || format_version != 0x00010d00
        || !(1..=256).contains(&image_count)
        || part_number != 1
        || total_parts != 1
    {
        return Err(WindowsIsoError::Corrupt);
    }
    Ok(WimHeader {
        image_count,
        format_version,
        part_number,
        total_parts,
        file_bytes: entry.length,
    })
}

fn check_efi_x64<R: Read + Seek>(file: &mut R, entry: &IsoFile) -> Result<bool, WindowsIsoError> {
    if !(256..=8 * 1024 * 1024).contains(&entry.length) {
        return Ok(false);
    }
    let mut first = [0u8; 4096];
    at(
        file,
        entry.offset,
        &mut first[..entry.length.min(4096) as usize],
    )?;
    if &first[..2] != b"MZ" {
        return Ok(false);
    }
    let pe = u32::from_le_bytes(first[0x3c..0x40].try_into().unwrap()) as usize;
    if pe > first.len() - 96 || pe as u64 + 96 > entry.length {
        return Ok(false);
    }
    Ok(&first[pe..pe + 4] == b"PE\0\0"
        && &first[pe + 4..pe + 6] == b"\x64\x86"
        && &first[pe + 24..pe + 26] == b"\x0b\x02"
        && u16::from_le_bytes([first[pe + 24 + 68], first[pe + 24 + 69]]) == 10)
}

// Recognize a UDF Volume Recognition Sequence even if it occurs after
// the ISO9660 terminator. This never enables UDF file extraction.
fn has_udf_vrs<R: Read + Seek>(file: &mut R, image_bytes: u64) -> Result<bool, WindowsIsoError> {
    let mut seen_bea = false;
    for lba in 16u64..64 {
        if (lba + 1) * 2048 > image_bytes {
            break;
        }
        let mut sig = [0u8; 6];
        at(file, lba * 2048, &mut sig)?;
        match &sig[1..] {
            b"BEA01" => seen_bea = true,
            b"NSR02" | b"NSR03" if seen_bea => return Ok(true),
            b"TEA01" => seen_bea = false,
            _ => (),
        }
    }
    Ok(false)
}

pub fn inspect<R: Read + Seek>(
    file: &mut R,
    image_bytes: u64,
) -> Result<WindowsIsoReport, WindowsIsoError> {
    if !(18 * 2048..=MAX_BOOT_IMAGE).contains(&image_bytes) {
        return Err(WindowsIsoError::Unsupported(
            "ISO length exceeds bounded range",
        ));
    }
    let iso = iso_inspect::inspect(file, image_bytes)?;
    let udf_observed = iso.udf_recognition || has_udf_vrs(file, image_bytes)?;
    let tree = iso_tree::enumerate_windows_metadata(file, image_bytes)?;
    let get = |path: &str| tree.files.iter().find(|entry| entry.path == path);
    let boot = get("SOURCES/BOOT.WIM");
    let install_wim = get("SOURCES/INSTALL.WIM");
    let install_esd = get("SOURCES/INSTALL.ESD");
    let efi = get("EFI/BOOT/BOOTX64.EFI");
    let boot_wim = boot.map(|x| parse_wim(file, x)).transpose()?;
    let install_wim = install_wim.map(|x| parse_wim(file, x)).transpose()?;
    let install_esd = install_esd.map(|x| parse_wim(file, x)).transpose()?;
    let loader_valid = if let Some(entry) = efi {
        check_efi_x64(file, entry)?
    } else {
        false
    };
    let setup_exe = get("SETUP.EXE").is_some();
    let complete_candidate = boot_wim.is_some()
        && (install_wim.is_some() ^ install_esd.is_some())
        && setup_exe
        && loader_valid
        && iso.uefi_catalog_entry;
    // UDF signatures alone do not grant filesystem traversal semantics.
    // A separate, audited UDF translator is required for UDF-bearing media.
    let eligible = complete_candidate && !udf_observed;
    let install_bytes = install_wim
        .as_ref()
        .or(install_esd.as_ref())
        .map(|w| w.file_bytes);
    let reason = if udf_observed {
        "udf_requires_independent_filesystem_qualification"
    } else if !complete_candidate {
        "windows_setup_candidate_incomplete_or_unverified"
    } else {
        "developer_only_virtual_cdrom_bit_exact_staging"
    };
    Ok(WindowsIsoReport {
        read_only: true,
        physical_write_authorized: false,
        windows_setup_boot_verified: false,
        windows_version_verified: false,
        image_bytes,
        scanned_files: tree.files.len(),
        observed_file_bytes: tree.total_bytes,
        source_filesystem: "iso9660_primary_metadata_only",
        udf_translation_supported: false,
        udf_signature_observed: udf_observed,
        el_torito_uefi_catalog: iso.uefi_catalog_entry,
        x64_efi_loader_header_valid: loader_valid,
        setup_exe_observed: setup_exe,
        boot_wim,
        install_wim,
        install_esd,
        installation_index_verified: false,
        wim_split_implemented: false,
        fat32_install_payload_compatible: if udf_observed {
            None
        } else {
            install_bytes.map(|bytes| bytes <= FAT32_FILE_MAX)
        },
        virtual_cdrom_staging_eligible: eligible,
        recommended_handling: reason,
    })
}

fn digest<R: Read + Seek>(source: &mut R) -> Result<String, WindowsIsoError> {
    source.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; CHUNK];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

pub fn stage_virtual_cdrom<R: Read + Seek, W: Read + Write + Seek>(
    source: &mut R,
    output: &mut W,
    length: u64,
) -> Result<(WindowsIsoReport, String), WindowsIsoError> {
    let report = inspect(source, length)?;
    if !report.virtual_cdrom_staging_eligible {
        return Err(WindowsIsoError::Unsupported(
            "media cannot be staged: requires supported plain ISO9660 tree, validated WIMs, x64 EFI and UEFI catalog",
        ));
    }
    let before = digest(source)?;
    output.seek(SeekFrom::Start(0))?;
    source.seek(SeekFrom::Start(0))?;
    let mut left = length;
    let mut buffer = [0u8; CHUNK];
    let mut staged = Sha256::new();
    while left > 0 {
        let count = left.min(CHUNK as u64) as usize;
        source.read_exact(&mut buffer[..count])?;
        output.write_all(&buffer[..count])?;
        staged.update(&buffer[..count]);
        left -= count as u64;
    }
    output.flush()?;
    let middle = hex::encode(staged.finalize());
    let after = digest(source)?;
    let readback = digest(output)?;
    if before != after || before != middle || before != readback {
        return Err(WindowsIsoError::Verification);
    }
    Ok((report, before))
}

#[cfg(test)]
#[path = "windows_iso_tests.rs"]
mod private_tests;
