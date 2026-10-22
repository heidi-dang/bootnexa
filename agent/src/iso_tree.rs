//! Strict ISO9660 primary-volume directory traversal for SMALL virtual EFI
//! media only. No UDF/Rock Ridge/Joliet translation, symbolic links, multi-
//! extent files, executable mounting, or storage-device APIs are allowed.
use crate::iso_inspect::{IsoError, inspect};
use serde::Serialize;
use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom},
};
use thiserror::Error;

pub const BLOCK: u64 = 2048;
pub const MAX_ENTRIES: usize = 512;
pub const MAX_DEPTH: usize = 8;
pub const MAX_TOTAL_BYTES: u64 = 60 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 48 * 1024 * 1024;
pub const MAX_DIRECTORY_BYTES: u64 = 1024 * 1024;
const MAX_ISO_BYTES: u64 = 128 * 1024 * 1024 * 1024;
#[derive(Debug, Error)]
pub enum TreeError {
    #[error("unsupported ISO9660 directory feature or unsafe path")]
    Unsupported,
    #[error("corrupt or ambiguous ISO9660 directory record")]
    Corrupt,
    #[error("ISO9660 file corpus exceeds bounded virtual capacity")]
    Capacity,
    #[error("ISO metadata classification failed: {0}")]
    Iso(#[from] IsoError),
    #[error("read-only ISO input I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IsoFile {
    pub path: String,
    pub offset: u64,
    pub length: u64,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IsoTree {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub files: Vec<IsoFile>,
    pub total_bytes: u64,
}
#[derive(Clone, Debug)]
struct Record {
    name: String,
    start: u64,
    size: u64,
    directory: bool,
}
fn dual_u32(bytes: &[u8]) -> Result<u64, TreeError> {
    if bytes.len() < 8 {
        return Err(TreeError::Corrupt);
    }
    let le = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let be = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if le != be {
        return Err(TreeError::Corrupt);
    }
    Ok(le as u64)
}
fn record(bytes: &[u8], image_bytes: u64) -> Result<Option<Record>, TreeError> {
    if bytes.len() < 34 || bytes[0] as usize != bytes.len() {
        return Err(TreeError::Corrupt);
    }
    let name_len = bytes[32] as usize;
    if name_len == 0 || 33 + name_len > bytes.len() {
        return Err(TreeError::Corrupt);
    }
    if bytes[1] != 0 || bytes[26] != 0 || bytes[27] != 0 || bytes[25] & !0x02 != 0 {
        // Extended attribute, interleave, multi-extent, special flags denied.
        return Err(TreeError::Unsupported);
    }
    if u16::from_le_bytes([bytes[28], bytes[29]]) != 1
        || u16::from_be_bytes([bytes[30], bytes[31]]) != 1
    {
        return Err(TreeError::Unsupported);
    }
    let start = dual_u32(&bytes[2..10])?
        .checked_mul(BLOCK)
        .ok_or(TreeError::Corrupt)?;
    let size = dual_u32(&bytes[10..18])?;
    let end = start.checked_add(size).ok_or(TreeError::Corrupt)?;
    if start == 0 || end > image_bytes {
        return Err(TreeError::Corrupt);
    }
    // System-use area (Rock Ridge, XA etc.) changes file semantics; fail
    // closed rather than silently copy links or truncate logical filenames.
    let nominal_end = 33 + name_len + (usize::from(name_len.is_multiple_of(2)));
    if bytes.len() < nominal_end || bytes[nominal_end..].iter().any(|&n| n != 0) {
        return Err(TreeError::Unsupported);
    }
    let name = &bytes[33..33 + name_len];
    if name_len == 1 && (name[0] == 0 || name[0] == 1) {
        return Ok(None);
    }
    if !name.is_ascii() {
        return Err(TreeError::Unsupported);
    }
    let text = std::str::from_utf8(name).map_err(|_| TreeError::Unsupported)?;
    // ISO9660 primary names include version suffix ;1 (directories don't).
    let text = if let Some((base, version)) = text.rsplit_once(';') {
        if version != "1" {
            return Err(TreeError::Unsupported);
        }
        base
    } else {
        text
    };
    let text = text.trim_end_matches('.');
    if text.is_empty()
        || text == "."
        || text == ".."
        || text.len() > 60
        || !text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
    {
        return Err(TreeError::Unsupported);
    }
    Ok(Some(Record {
        name: text.to_ascii_uppercase(),
        start,
        size,
        directory: bytes[25] & 0x02 != 0,
    }))
}
fn read_at<R: Read + Seek>(r: &mut R, pos: u64, out: &mut [u8]) -> Result<(), TreeError> {
    r.seek(SeekFrom::Start(pos))?;
    r.read_exact(out)?;
    Ok(())
}
pub fn enumerate<R: Read + Seek>(r: &mut R, length: u64) -> Result<IsoTree, TreeError> {
    if !(18 * BLOCK..=MAX_ISO_BYTES).contains(&length) {
        return Err(TreeError::Unsupported);
    }
    let classification = inspect(r, length)?;
    if !classification.iso9660 {
        return Err(TreeError::Unsupported);
    }
    let mut pvd = [0u8; 2048];
    read_at(r, 16 * BLOCK, &mut pvd)?;
    if pvd[0] != 1 || &pvd[1..6] != b"CD001" || pvd[6] != 1 {
        return Err(TreeError::Unsupported);
    }
    let root_len = pvd[156] as usize;
    if !(34..=255).contains(&root_len) || 156 + root_len > pvd.len() {
        return Err(TreeError::Corrupt);
    }
    let root = record(&pvd[156..156 + root_len], length)?;
    // Root is represented by special ISO entry "\0", which record() skips:
    // re-check root flags/extent/size directly under the same validation path.
    if root.is_some() || pvd[156 + 32] != 1 || pvd[156 + 33] != 0 || pvd[156 + 25] & 2 == 0 {
        return Err(TreeError::Corrupt);
    }
    let root_offset = dual_u32(&pvd[156 + 2..156 + 10])?
        .checked_mul(BLOCK)
        .ok_or(TreeError::Corrupt)?;
    let root_size = dual_u32(&pvd[156 + 10..156 + 18])?;
    if root_size == 0
        || root_size > MAX_DIRECTORY_BYTES
        || root_offset
            .checked_add(root_size)
            .is_none_or(|end| end > length)
    {
        return Err(TreeError::Corrupt);
    }
    let mut pending = vec![(String::new(), root_offset, root_size, 0usize)];
    let mut visited = HashSet::new();
    // Validate all observed data extents as disjoint. Reject files that alias
    // directory records, primary volume descriptor sectors or other files.
    let mut extents = vec![(16 * BLOCK, 20 * BLOCK)];
    let mut names = HashSet::new();
    let mut tree = IsoTree {
        read_only: true,
        physical_write_authorized: false,
        files: vec![],
        total_bytes: 0,
    };
    while let Some((prefix, offset, size, depth)) = pending.pop() {
        if depth > MAX_DEPTH
            || size == 0
            || size > MAX_DIRECTORY_BYTES
            || !visited.insert((offset, size))
        {
            return Err(TreeError::Unsupported);
        }
        extents.push((offset, offset.checked_add(size).ok_or(TreeError::Corrupt)?));
        let mut directory = vec![0u8; size as usize];
        read_at(r, offset, &mut directory)?;
        let mut position = 0usize;
        while position < directory.len() {
            let len = directory[position] as usize;
            if len == 0 {
                let end = ((position / BLOCK as usize) + 1) * BLOCK as usize;
                if directory[position..end.min(directory.len())]
                    .iter()
                    .any(|&c| c != 0)
                {
                    return Err(TreeError::Corrupt);
                }
                position = end;
                continue;
            }
            if len < 34
                || position + len > directory.len()
                || position / BLOCK as usize != (position + len - 1) / BLOCK as usize
            {
                return Err(TreeError::Corrupt);
            }
            let entry = record(&directory[position..position + len], length)?;
            position += len;
            let Some(entry) = entry else { continue };
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{prefix}/{}", entry.name)
            };
            if path.len() > 240 || !names.insert(path.clone()) {
                return Err(TreeError::Unsupported);
            }
            if names.len() > MAX_ENTRIES {
                return Err(TreeError::Capacity);
            }
            if entry.directory {
                if depth >= MAX_DEPTH {
                    return Err(TreeError::Capacity);
                }
                pending.push((path, entry.start, entry.size, depth + 1));
            } else {
                if entry.size > MAX_FILE_BYTES {
                    return Err(TreeError::Capacity);
                }
                tree.total_bytes = tree
                    .total_bytes
                    .checked_add(entry.size)
                    .ok_or(TreeError::Capacity)?;
                if tree.total_bytes > MAX_TOTAL_BYTES {
                    return Err(TreeError::Capacity);
                }
                if entry.size > 0 {
                    extents.push((
                        entry.start,
                        entry
                            .start
                            .checked_add(entry.size)
                            .ok_or(TreeError::Corrupt)?,
                    ));
                }
                tree.files.push(IsoFile {
                    path,
                    offset: entry.start,
                    length: entry.size,
                });
                if tree.files.len() > MAX_ENTRIES {
                    return Err(TreeError::Capacity);
                }
            }
        }
    }
    extents.sort_unstable();
    if extents.windows(2).any(|ab| ab[0].1 > ab[1].0) {
        return Err(TreeError::Corrupt);
    }
    tree.files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    Ok(tree)
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaPlan {
    pub profile: String,
    pub virtual_efi_eligible: bool,
    pub windows_setup_verified: bool,
    pub linux_boot_verified: bool,
    pub physical_write_authorized: bool,
    pub reason: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub requires_wim_split: bool,
}
pub fn classify(tree: &IsoTree) -> MediaPlan {
    let names = tree
        .files
        .iter()
        .map(|f| f.path.as_str())
        .collect::<HashSet<_>>();
    let windows = names.contains("SOURCES/BOOT.WIM")
        || names.contains("SOURCES/INSTALL.WIM")
        || names.contains("SOURCES/INSTALL.ESD");
    let linux = names.contains("CASPER/VMLINUZ")
        || names.contains("ISOLINUX/ISOLINUX.BIN")
        || names.contains("BOOT/GRUB/GRUB.CFG");
    let efi = names.contains("EFI/BOOT/BOOTX64.EFI");
    let oversized_wim = tree
        .files
        .iter()
        .any(|f| f.path.ends_with(".WIM") && f.length >= 4 * 1024 * 1024 * 1024);
    let profile = if windows {
        "windows_install_candidate"
    } else if linux {
        "linux_distribution_candidate"
    } else if efi {
        "efi_application_virtual_only"
    } else {
        "unsupported_boot_layout"
    };
    let eligible =
        efi && !windows && !linux && !oversized_wim && tree.total_bytes <= MAX_TOTAL_BYTES;
    let reason = if windows {
        "Windows installer detected: WIM/ESD and Setup validation required; no installer production or copying authorized"
    } else if linux {
        "Linux boot layout detected: bootloader, hybrid filesystem and kernel compatibility not qualified"
    } else if eligible {
        "Small ISO9660 x64 EFI payload: eligible for virtual-only extraction; boot under OVMF separately"
    } else {
        "Missing supported EFI/BOOT/BOOTX64.EFI payload or unsupported ISO layout"
    };
    MediaPlan {
        profile: profile.into(),
        virtual_efi_eligible: eligible,
        windows_setup_verified: false,
        linux_boot_verified: false,
        physical_write_authorized: false,
        reason: reason.into(),
        file_count: tree.files.len(),
        total_bytes: tree.total_bytes,
        requires_wim_split: oversized_wim,
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;
    fn dual(data: &mut [u8], value: u32) {
        data[..4].copy_from_slice(&value.to_le_bytes());
        data[4..8].copy_from_slice(&value.to_be_bytes());
    }
    fn rec(start: u32, len: u32, name: &[u8], directory: bool) -> Vec<u8> {
        let mut out = vec![0u8; 33 + name.len() + usize::from(name.len().is_multiple_of(2))];
        out[0] = out.len() as u8;
        dual(&mut out[2..10], start);
        dual(&mut out[10..18], len);
        out[25] = if directory { 2 } else { 0 };
        out[28..30].copy_from_slice(&1u16.to_le_bytes());
        out[30..32].copy_from_slice(&1u16.to_be_bytes());
        out[32] = name.len() as u8;
        out[33..33 + name.len()].copy_from_slice(name);
        out
    }
    pub(crate) fn fixture() -> Vec<u8> {
        let mut iso = vec![0u8; 80 * 2048];
        let pvd = 16 * 2048;
        iso[pvd] = 1;
        iso[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        iso[pvd + 6] = 1;
        iso[pvd + 40..pvd + 72].fill(b' ');
        let root = rec(22, 2048, &[0], true);
        iso[pvd + 156..pvd + 156 + root.len()].copy_from_slice(&root);
        iso[17 * 2048] = 255;
        iso[17 * 2048 + 1..17 * 2048 + 6].copy_from_slice(b"CD001");
        iso[17 * 2048 + 6] = 1;
        // Fix actual path: root has EFI; EFI has BOOT; BOOT has PE file
        let root_pos = 22 * 2048;
        iso[root_pos..root_pos + 2048].fill(0);
        let efi = rec(23, 2048, b"EFI", true);
        iso[root_pos..root_pos + efi.len()].copy_from_slice(&efi);
        let efi_pos = 23 * 2048;
        iso[efi_pos..efi_pos + 2048].fill(0);
        let boot = rec(24, 2048, b"BOOT", true);
        iso[efi_pos..efi_pos + boot.len()].copy_from_slice(&boot);
        let boot_pos = 24 * 2048;
        iso[boot_pos..boot_pos + 2048].fill(0);
        let file = rec(30, 4096, b"BOOTX64.EFI;1", false);
        iso[boot_pos..boot_pos + file.len()].copy_from_slice(&file);
        iso[30 * 2048..32 * 2048].fill(0xA5);
        let app = &mut iso[30 * 2048..32 * 2048];
        app[..2].copy_from_slice(b"MZ");
        app[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        app[0x80..0x84].copy_from_slice(b"PE\0\0");
        app[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        app[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        app[0x98 + 68..0x98 + 70].copy_from_slice(&10u16.to_le_bytes());
        iso
    }
    #[test]
    fn bounded_tree_and_plan() {
        let bytes = fixture();
        let tree = enumerate(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap();
        assert_eq!(tree.files[0].path, "EFI/BOOT/BOOTX64.EFI");
        assert_eq!(tree.files[0].length, 4096);
        assert!(classify(&tree).virtual_efi_eligible);
        assert!(!classify(&tree).physical_write_authorized);
    }
    #[test]
    fn unsafe_layouts_and_size_mismatch_reject() {
        for pos in [16 * 2048 + 156 + 2, 24 * 2048 + 2, 24 * 2048 + 25] {
            let mut bytes = fixture();
            bytes[pos] ^= 0x80;
            assert!(
                enumerate(&mut Cursor::new(&bytes), bytes.len() as u64).is_err(),
                "offset {pos}"
            );
        }
        let mut bytes = fixture();
        bytes[24 * 2048 + 33] = b'/';
        assert!(enumerate(&mut Cursor::new(&bytes), bytes.len() as u64).is_err());
        let mut bytes = fixture();
        let extent = 24 * 2048 + 10;
        dual(&mut bytes[extent..extent + 8], u32::MAX);
        assert!(enumerate(&mut Cursor::new(&bytes), bytes.len() as u64).is_err());
    }
    #[test]
    fn excessive_empty_directory_entries_fail_closed() {
        let mut image = fixture();
        image.resize(1200 * 2048, 0);
        let pvd = 16 * 2048;
        dual(&mut image[pvd + 156 + 10..pvd + 156 + 18], 64 * 1024);
        let root_start = 22 * 2048;
        image[root_start..root_start + 64 * 1024].fill(0);
        let mut pos = root_start;
        for i in 0..=MAX_ENTRIES {
            let name = format!("D{i:04}");
            let entry = rec((600 + i) as u32, 2048, name.as_bytes(), true);
            let within = (pos - root_start) % 2048;
            if within + entry.len() > 2048 {
                pos += 2048 - within;
            }
            image[pos..pos + entry.len()].copy_from_slice(&entry);
            pos += entry.len();
        }
        assert!(matches!(
            enumerate(&mut Cursor::new(&image), image.len() as u64),
            Err(TreeError::Capacity)
        ));
    }
    #[test]
    fn rejects_duplicate_alias_and_untrusted_user_name() {
        let mut bytes = fixture();
        let boot_pos = 24 * 2048;
        let rec_len = bytes[boot_pos] as usize;
        let duplicate = bytes[boot_pos..boot_pos + rec_len].to_vec();
        bytes[boot_pos + rec_len..boot_pos + rec_len * 2].copy_from_slice(&duplicate);
        assert!(enumerate(&mut Cursor::new(&bytes), bytes.len() as u64).is_err());
    }
}
