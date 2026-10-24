//! Bounded read-only ECMA-167/UDF File Identifier Descriptor traversal.
//! No file-content extraction, no symlinks, no device handles or write authority.
//! Only the restricted UDF single-partition/2KiB-block profile qualified by
//! udf_structure is eligible. Unhandled variants fail closed.
use crate::udf_structure::{
    self, UdfError, UdfVolume, crc16, partition_lba, sector, tag, u16_at, u32_at,
};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;

const BLOCK: u64 = 2048;
const MAX_PATHS: usize = 2048;
const MAX_DEPTH: usize = 8;
const MAX_DIR_BYTES: u64 = 1024 * 1024;
const MAX_DIR_TOTAL: u64 = 16 * 1024 * 1024;
const MAX_EXTENTS: usize = 128;
const MAX_PATH_BYTES: usize = 240;

#[derive(Debug, Error)]
pub enum UdfTreeError {
    #[error("UDF descriptor-chain verification failed: {0}")]
    Descriptor(#[from] UdfError),
    #[error("unsupported UDF file-entry or directory feature")]
    Unsupported,
    #[error("corrupt or overlapping UDF file entry, extent or file identifier")]
    Corrupt,
    #[error("read-only UDF metadata I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdfPath {
    pub path: String,
    pub file_bytes: u64,
    pub directory: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdfTree {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub file_extraction_supported: bool,
    pub virtual_usb_builder_implemented: bool,
    pub windows_setup_boot_verified: bool,
    pub root_directory_traversal_verified: bool,
    pub partition_number: u16,
    pub inspected_paths: usize,
    pub inspected_directories: usize,
    pub directory_bytes_read: u64,
    pub file_paths: Vec<UdfPath>,
    pub windows_setup_filename_candidate: bool,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct Extent {
    pub(crate) block: u32,
    pub(crate) bytes: u32,
}
#[derive(Debug)]
pub(crate) struct Inode {
    pub(crate) kind: u8,
    pub(crate) size: u64,
    pub(crate) extents: Vec<Extent>,
}
fn extent_abs(
    block: u32,
    bytes: u32,
    vol: &UdfVolume,
    image_bytes: u64,
) -> Result<u64, UdfTreeError> {
    if bytes == 0 {
        return Err(UdfTreeError::Corrupt);
    }
    let count = u64::from(bytes).div_ceil(BLOCK);
    if u64::from(block)
        .checked_add(count)
        .is_none_or(|n| n > u64::from(vol.partition_blocks))
    {
        return Err(UdfTreeError::Corrupt);
    }
    let lba = partition_lba(
        block,
        vol.partition_start_lba,
        vol.partition_blocks,
        image_bytes,
    )?;
    Ok(lba * BLOCK)
}
pub(crate) fn checked_inode<R: Read + Seek>(
    reader: &mut R,
    vol: &UdfVolume,
    image_bytes: u64,
    block: u32,
) -> Result<Inode, UdfTreeError> {
    let lba = partition_lba(
        block,
        vol.partition_start_lba,
        vol.partition_blocks,
        image_bytes,
    )?;
    let data = sector(reader, image_bytes, lba)?;
    tag(&data, u64::from(block), 261)?;
    let kind = data[27];
    if !matches!(kind, 4 | 5) {
        return Err(UdfTreeError::Unsupported);
    }
    let flags = u16_at(&data, 34);
    if flags & !7 != 0 || flags & 7 > 1 {
        return Err(UdfTreeError::Unsupported);
    }
    let size = u64::from_le_bytes(data[56..64].try_into().unwrap());
    if size > image_bytes || (kind == 4 && size > MAX_DIR_BYTES) {
        return Err(UdfTreeError::Unsupported);
    }
    let ea = u32_at(&data, 168) as usize;
    let len = u32_at(&data, 172) as usize;
    let stride: usize = if flags & 7 == 0 { 8 } else { 16 };
    let start = 176usize.checked_add(ea).ok_or(UdfTreeError::Corrupt)?;
    let end = start.checked_add(len).ok_or(UdfTreeError::Corrupt)?;
    let covered = 16usize
        .checked_add(u16_at(&data, 10) as usize)
        .ok_or(UdfTreeError::Corrupt)?;
    if ea > 0
        || !len.is_multiple_of(stride)
        || len / stride > MAX_EXTENTS
        || end > data.len()
        || end > covered
    {
        return Err(UdfTreeError::Unsupported);
    }
    let mut extents = Vec::new();
    let mut accumulated = 0u64;
    for pos in (start..end).step_by(stride) {
        let bytes_with_flags = u32_at(&data, pos);
        if bytes_with_flags >> 30 != 0 {
            return Err(UdfTreeError::Unsupported);
        }
        let bytes = bytes_with_flags & 0x3fff_ffff;
        let block = u32_at(&data, pos + 4);
        if stride == 16 && u16_at(&data, pos + 8) != vol.partition_number {
            return Err(UdfTreeError::Unsupported);
        }
        let _ = extent_abs(block, bytes, vol, image_bytes)?;
        accumulated = accumulated
            .checked_add(u64::from(bytes))
            .ok_or(UdfTreeError::Corrupt)?;
        extents.push(Extent { block, bytes });
    }
    if accumulated != size {
        return Err(UdfTreeError::Corrupt);
    }
    Ok(Inode {
        kind,
        size,
        extents,
    })
}
fn filename(encoded: &[u8]) -> Result<String, UdfTreeError> {
    if encoded.len() < 2 {
        return Err(UdfTreeError::Unsupported);
    }
    let codes: Vec<u32> = match encoded[0] {
        8 => encoded[1..].iter().map(|&v| u32::from(v)).collect(),
        16 if (encoded.len() - 1).is_multiple_of(2) => encoded[1..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u32::from(u16::from_be_bytes(*p)))
            .collect(),
        _ => return Err(UdfTreeError::Unsupported),
    };
    if codes.is_empty() || codes.len() > 120 {
        return Err(UdfTreeError::Unsupported);
    }
    let mut name = String::new();
    for code in codes {
        // Restricted ASCII subset: Unicode normalization and case folding
        // require a separate security review before localized Windows names.
        if !(0x20..=0x7e).contains(&code) {
            return Err(UdfTreeError::Unsupported);
        }
        let c = char::from_u32(code).ok_or(UdfTreeError::Unsupported)?;
        if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ')) {
            return Err(UdfTreeError::Unsupported);
        }
        name.push(c.to_ascii_uppercase());
    }
    if matches!(name.as_str(), "." | "..")
        || name.starts_with(' ')
        || name.ends_with(' ')
        || name.ends_with('.')
        || name.len() > 120
    {
        return Err(UdfTreeError::Unsupported);
    }
    Ok(name)
}
pub(crate) type FidName = (String, u32, bool);

pub(crate) fn checked_fid(
    data: &[u8],
    pos: usize,
    logical_block: u64,
    partition_number: u16,
) -> Result<(usize, Option<FidName>), UdfTreeError> {
    if data.len().saturating_sub(pos) < 38 {
        return Err(UdfTreeError::Corrupt);
    }
    let h = &data[pos..];
    if u16_at(h, 0) != 257
        || !matches!(u16_at(h, 2), 2 | 3)
        || u32_at(h, 12) as u64 != logical_block
        || h[5] != 0
        || u16_at(h, 16) != 1
    {
        return Err(UdfTreeError::Corrupt);
    }
    let sum = h[..16]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .fold(0u8, |sum, (_, value)| sum.wrapping_add(*value));
    let flags = h[18];
    let n = h[19] as usize;
    let imp = u16_at(h, 36) as usize;
    if flags & !0x0b != 0 || flags & 0x04 != 0 || imp != 0 {
        return Err(UdfTreeError::Unsupported);
    }
    let unpadded = 38usize.checked_add(n).ok_or(UdfTreeError::Corrupt)?;
    let total = unpadded.checked_add(3).ok_or(UdfTreeError::Corrupt)? & !3;
    let crc_bytes = u16_at(h, 10) as usize;
    if total > h.len()
        || pos % 2048 + total > 2048
        || crc_bytes != unpadded - 16
        || sum != h[4]
        || crc16(&h[16..16 + crc_bytes]) != u16_at(h, 8)
        || h[unpadded..total].iter().any(|&v| v != 0)
    {
        return Err(UdfTreeError::Corrupt);
    }
    if flags & 0x08 != 0 {
        if n != 0 || flags & 0x02 == 0 {
            return Err(UdfTreeError::Corrupt);
        }
        return Ok((total, None));
    }
    if n == 0
        || u16_at(h, 28) != partition_number
        || (u32_at(h, 20) & 0x3fff_ffff) != 2048
        || (u32_at(h, 20) >> 30) != 0
    {
        return Err(UdfTreeError::Unsupported);
    }
    let name = filename(&h[38..38 + n])?;
    let icb_block = u32_at(h, 24);
    Ok((total, Some((name, icb_block, flags & 0x02 != 0))))
}
pub fn inspect<R: Read + Seek>(source: &mut R, image_bytes: u64) -> Result<UdfTree, UdfTreeError> {
    let vol = udf_structure::inspect(source, image_bytes)?;
    let root_block = vol
        .root_icb_lba
        .checked_sub(vol.partition_start_lba)
        .ok_or(UdfTreeError::Corrupt)?;
    let mut pending = VecDeque::from([(String::new(), root_block, 0usize)]);
    let mut icbs = HashSet::from([root_block]);
    let mut processed_dirs = HashSet::new();
    let mut named = HashSet::new();
    let mut extents = Vec::<(u64, u64)>::new();
    let mut files = Vec::<UdfPath>::new();
    let mut directories = 0usize;
    let mut scanned_dir_bytes = 0u64;
    while let Some((prefix, block, depth)) = pending.pop_front() {
        if !processed_dirs.insert(block) || icbs.len() > MAX_PATHS + 1 || depth > MAX_DEPTH {
            return Err(UdfTreeError::Unsupported);
        }
        let node = checked_inode(source, &vol, image_bytes, block)?;
        if node.kind != 4 {
            return Err(UdfTreeError::Corrupt);
        }
        directories += 1;
        scanned_dir_bytes = scanned_dir_bytes
            .checked_add(node.size)
            .ok_or(UdfTreeError::Corrupt)?;
        if scanned_dir_bytes > MAX_DIR_TOTAL {
            return Err(UdfTreeError::Unsupported);
        }
        for part in &node.extents {
            let start = extent_abs(part.block, part.bytes, &vol, image_bytes)?;
            let end = start + u64::from(part.bytes).div_ceil(BLOCK) * BLOCK;
            extents.push((start, end));
        }
        let dir_bytes = checked_dir_bytes(source, &vol, image_bytes, &node)?;
        let mut pos = 0usize;
        while pos < dir_bytes.len() {
            let block_end = ((pos / 2048) + 1) * 2048;
            if dir_bytes[pos] == 0 {
                let end = block_end.min(dir_bytes.len());
                if dir_bytes[pos..end].iter().any(|&v| v != 0) {
                    return Err(UdfTreeError::Corrupt);
                }
                pos = end;
                continue;
            }
            let (logical_location, segment_left) = logical_dir_sector(&node.extents, pos)?;
            let (record_len, fid) =
                checked_fid(&dir_bytes, pos, logical_location, vol.partition_number)?;
            if record_len > segment_left {
                return Err(UdfTreeError::Corrupt);
            }
            pos += record_len;
            let Some((name, icb_block, is_dir)) = fid else {
                continue;
            };
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if path.len() > MAX_PATH_BYTES || !named.insert(path.clone()) || named.len() > MAX_PATHS
            {
                return Err(UdfTreeError::Unsupported);
            }
            let child = checked_inode(source, &vol, image_bytes, icb_block)?;
            if (child.kind == 4) != is_dir || !icbs.insert(icb_block) {
                return Err(UdfTreeError::Corrupt);
            }
            // All sectors occupied by file extents must be unique across
            // files in this restricted UDF variant (hard links unsupported).
            if !is_dir {
                for part in &child.extents {
                    let start = extent_abs(part.block, part.bytes, &vol, image_bytes)?;
                    let end = start + u64::from(part.bytes).div_ceil(BLOCK) * BLOCK;
                    extents.push((start, end));
                }
            }
            files.push(UdfPath {
                path: path.clone(),
                file_bytes: child.size,
                directory: is_dir,
            });
            if is_dir {
                if depth >= MAX_DEPTH {
                    return Err(UdfTreeError::Unsupported);
                }
                pending.push_back((path, icb_block, depth + 1));
            }
        }
    }
    let protected_sectors = icbs
        .iter()
        .map(|&relative| u64::from(vol.partition_start_lba) + u64::from(relative))
        .chain([u64::from(vol.file_set_descriptor_lba)])
        .collect::<Vec<_>>();
    if extents.iter().any(|&(start, end)| {
        protected_sectors
            .iter()
            .any(|&lba| lba * BLOCK >= start && lba * BLOCK < end)
    }) {
        return Err(UdfTreeError::Corrupt);
    }
    extents.sort_unstable();
    if extents.windows(2).any(|p| p[0].1 > p[1].0) {
        return Err(UdfTreeError::Corrupt);
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let names: HashSet<&str> = files
        .iter()
        .filter(|p| !p.directory)
        .map(|p| p.path.as_str())
        .collect();
    let windows_candidate = names.contains("SOURCES/BOOT.WIM")
        && (names.contains("SOURCES/INSTALL.WIM") ^ names.contains("SOURCES/INSTALL.ESD"))
        && names.contains("EFI/BOOT/BOOTX64.EFI")
        && names.contains("SETUP.EXE");
    Ok(UdfTree {
        read_only: true,
        physical_write_authorized: false,
        file_extraction_supported: false,
        virtual_usb_builder_implemented: false,
        windows_setup_boot_verified: false,
        root_directory_traversal_verified: true,
        partition_number: vol.partition_number,
        inspected_paths: files.len(),
        inspected_directories: directories,
        directory_bytes_read: scanned_dir_bytes,
        file_paths: files,
        windows_setup_filename_candidate: windows_candidate,
    })
}
pub(crate) fn logical_dir_sector(
    extents: &[Extent],
    offset: usize,
) -> Result<(u64, usize), UdfTreeError> {
    let mut start = 0usize;
    for part in extents {
        let end = start
            .checked_add(part.bytes as usize)
            .ok_or(UdfTreeError::Corrupt)?;
        if (start..end).contains(&offset) {
            let left_in_sector = BLOCK as usize - (offset - start) % BLOCK as usize;
            return Ok((
                u64::from(part.block) + (offset - start) as u64 / BLOCK,
                (end - offset).min(left_in_sector),
            ));
        }
        start = end;
    }
    Err(UdfTreeError::Corrupt)
}
#[cfg(test)]
#[path = "udf_tree_tests.rs"]
mod tests;

pub(crate) fn checked_dir_bytes<R: Read + Seek>(
    source: &mut R,
    vol: &UdfVolume,
    image_bytes: u64,
    node: &Inode,
) -> Result<Vec<u8>, UdfTreeError> {
    let size = usize::try_from(node.size).map_err(|_| UdfTreeError::Unsupported)?;
    if size > MAX_DIR_BYTES as usize {
        return Err(UdfTreeError::Unsupported);
    }
    let mut bytes = Vec::with_capacity(size);
    for part in &node.extents {
        let absolute = extent_abs(part.block, part.bytes, vol, image_bytes)?;
        let n = part.bytes as usize;
        let offset = bytes.len();
        bytes.resize(offset + n, 0);
        source.seek(SeekFrom::Start(absolute))?;
        source.read_exact(&mut bytes[offset..offset + n])?;
    }
    if bytes.len() != size {
        return Err(UdfTreeError::Corrupt);
    }
    Ok(bytes)
}
