//! Developer-only, verified WIM->SWM archives through wimlib.
//! Writes only newly created regular files in a new temp directory.
//! No device targets, Microsoft media distribution, or Setup boot claims.
use crate::windows_media_plan::FAT32_MAX_SINGLE_FILE;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const MAX_SOURCE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PARTS: usize = 64;
const MAX_TOTAL: u64 = 20 * 1024 * 1024 * 1024;
const MAX_SECONDS: u64 = 1800;
const MAX_MIB: u32 = 3800;

#[derive(Debug, Error)]
pub enum SwmError {
    #[error("invalid WIM source, directory, or split size")]
    Invalid,
    #[error("wimlib-imagex not installed, or WIM parser rejected the archive")]
    Tool,
    #[error("wimlib verification time limit exceeded")]
    Timeout,
    #[error("source changed or SWM part failed FAT32/sha256 bounds")]
    Verification,
    #[error("WIM/SWM I/O error: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitPart {
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitReceipt {
    pub virtual_only: bool,
    pub physical_write_authorized: bool,
    pub installer_compatible_verified: bool,
    pub windows_setup_boot_verified: bool,
    pub split_wim_integrity_verified: bool,
    pub full_wim_resource_validation_tool: &'static str,
    pub source_bytes: u64,
    pub source_sha256: String,
    pub part_target_mib: u32,
    pub fat32_max_single_file_bytes: u64,
    pub all_parts_fit_fat32: bool,
    pub output_directory: PathBuf,
    pub parts: Vec<SplitPart>,
}
fn hash_file(path: &Path, limit: u64) -> Result<(u64, String), SwmError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(SwmError::Invalid);
    }
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 || size > limit {
        return Err(SwmError::Invalid);
    }
    let mut sha = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or(SwmError::Verification)?;
        if total > limit {
            return Err(SwmError::Verification);
        }
        sha.update(&buf[..n]);
    }
    if total != size {
        return Err(SwmError::Verification);
    }
    Ok((total, hex::encode(sha.finalize())))
}
fn invoke(parts: &[&std::ffi::OsStr]) -> Result<(), SwmError> {
    let mut child = Command::new("wimlib-imagex")
        .args(parts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| SwmError::Tool)?;
    let deadline = Instant::now() + Duration::from_secs(MAX_SECONDS);
    loop {
        match child.try_wait()? {
            Some(s) if s.success() => return Ok(()),
            Some(_) => return Err(SwmError::Tool),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SwmError::Timeout);
            }
            None => thread::sleep(Duration::from_millis(100)),
        }
    }
}
fn name(index: usize) -> String {
    if index == 1 {
        "install.swm".into()
    } else {
        format!("install{index}.swm")
    }
}
fn verify_parts(dir: &Path) -> Result<Vec<SplitPart>, SwmError> {
    let mut filenames = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(SwmError::Verification);
        }
        filenames.push(entry.file_name().to_string_lossy().into_owned());
    }
    if filenames.is_empty() || filenames.len() > MAX_PARTS {
        return Err(SwmError::Verification);
    }
    let mut result = Vec::new();
    let mut total = 0u64;
    for i in 1..=filenames.len() {
        let filename = name(i);
        if !filenames.contains(&filename) {
            return Err(SwmError::Verification);
        }
        let (bytes, sha256) = hash_file(&dir.join(&filename), FAT32_MAX_SINGLE_FILE)
            .map_err(|_| SwmError::Verification)?;
        total = total.checked_add(bytes).ok_or(SwmError::Verification)?;
        if total > MAX_TOTAL {
            return Err(SwmError::Verification);
        }
        result.push(SplitPart {
            filename,
            bytes,
            sha256,
        });
    }
    Ok(result)
}
/// Re-verify an already-produced split archive before it is consumed by
/// an anonymous virtual-media writer. Never trusts filenames alone.
pub fn verify_existing_split(dir: &Path) -> Result<Vec<SplitPart>, SwmError> {
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(SwmError::Invalid);
    }
    let parts = verify_parts(dir)?;
    let first = dir.join("install.swm");
    let references = format!("--ref={}", dir.join("install*.swm").display());
    invoke(&[
        std::ffi::OsStr::new("verify"),
        first.as_os_str(),
        std::ffi::OsStr::new(&references),
    ])?;
    let after = verify_parts(dir)?;
    if parts.len() != after.len()
        || parts
            .iter()
            .zip(&after)
            .any(|(a, b)| a.filename != b.filename || a.bytes != b.bytes || a.sha256 != b.sha256)
    {
        return Err(SwmError::Verification);
    }
    Ok(parts)
}

/// Validate a read-only WIM with wimlib's resource verification engine.
pub fn verify_existing_wim(source: &Path, max_bytes: u64) -> Result<SplitPart, SwmError> {
    let (bytes, before) = hash_file(source, max_bytes.min(MAX_SOURCE))?;
    invoke(&[std::ffi::OsStr::new("verify"), source.as_os_str()])?;
    if hash_file(source, max_bytes.min(MAX_SOURCE))? != (bytes, before.clone()) {
        return Err(SwmError::Verification);
    }
    Ok(SplitPart {
        filename: "boot.wim".into(),
        bytes,
        sha256: before,
    })
}

/// Run a qualified WIM parser and split into FAT32-bounded SWMs.
pub fn qualify_split(
    source: &Path,
    output_parent: &Path,
    mib: u32,
) -> Result<SplitReceipt, SwmError> {
    if !(1..=MAX_MIB).contains(&mib)
        || !fs::symlink_metadata(output_parent)?.file_type().is_dir()
        || !fs::symlink_metadata(source)?.file_type().is_file()
    {
        return Err(SwmError::Invalid);
    }
    let source = fs::canonicalize(source)?;
    let destination = fs::canonicalize(output_parent)?;
    let (source_bytes, digest) = hash_file(&source, MAX_SOURCE)?;
    invoke(&[std::ffi::OsStr::new("verify"), source.as_os_str()])?;
    let temp = tempfile::Builder::new()
        .prefix("bootnexa-swm-")
        .tempdir_in(&destination)?;
    let first = temp.path().join("install.swm");
    let part_mib = mib.to_string();
    invoke(&[
        std::ffi::OsStr::new("split"),
        source.as_os_str(),
        first.as_os_str(),
        std::ffi::OsStr::new(&part_mib),
        std::ffi::OsStr::new("--check"),
    ])?;
    // wimlib can exceed the requested part-size if a compressed resource is
    // indivisible, so always validate the *actual* byte length.
    let parts = verify_parts(temp.path())?;
    let reference_arg = format!("--ref={}", temp.path().join("install*.swm").display());
    invoke(&[
        std::ffi::OsStr::new("verify"),
        first.as_os_str(),
        std::ffi::OsStr::new(&reference_arg),
    ])?;
    if hash_file(&source, MAX_SOURCE)? != (source_bytes, digest.clone()) {
        return Err(SwmError::Verification);
    }
    let reread = verify_parts(temp.path())?;
    if parts.len() != reread.len()
        || parts
            .iter()
            .zip(&reread)
            .any(|(a, b)| a.filename != b.filename || a.bytes != b.bytes || a.sha256 != b.sha256)
    {
        return Err(SwmError::Verification);
    }
    for part in &parts {
        File::open(temp.path().join(&part.filename))?.sync_all()?;
    }
    let output_directory = temp.keep();
    Ok(SplitReceipt {
        virtual_only: true,
        physical_write_authorized: false,
        installer_compatible_verified: false,
        windows_setup_boot_verified: false,
        split_wim_integrity_verified: true,
        full_wim_resource_validation_tool: "wimlib-imagex verify",
        source_bytes,
        source_sha256: digest,
        part_target_mib: mib,
        fat32_max_single_file_bytes: FAT32_MAX_SINGLE_FILE,
        all_parts_fit_fat32: true,
        output_directory,
        parts,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn splitting_requires_valid_size_and_contiguous_parts() {
        assert_eq!(name(1), "install.swm");
        assert_eq!(name(2), "install2.swm");
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("invalid.wim");
        fs::write(&source, b"MSWIM").unwrap();
        assert!(matches!(
            qualify_split(&source, dir.path(), 0),
            Err(SwmError::Invalid)
        ));
        assert!(matches!(
            qualify_split(&source, dir.path(), 3801),
            Err(SwmError::Invalid)
        ));
        fs::write(dir.path().join("install.swm"), b"aa").unwrap();
        fs::write(dir.path().join("install3.swm"), b"cc").unwrap();
        assert!(verify_parts(dir.path()).is_err());
    }
}
