//! Bounded, verified UDF source reader for anonymous virtual-media tests.
//! No device paths, target path handling, external writes or installer claims.
//! Each stream is constructed from a freshly validated whole UDF tree.
use crate::udf_structure::{self, partition_lba};
use crate::udf_tree::{self, UdfTreeError};
use std::io::{self, Read, Seek, SeekFrom};

const BLOCK: u64 = 2048;
const MAX_FILE: u64 = 48 * 1024 * 1024;
const MAX_EXTENTS: usize = 128;

fn fault(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
#[derive(Clone, Copy)]
struct Span {
    absolute: u64,
    bytes: u64,
}
pub(crate) struct CheckedUdfSource<'a, R: Read + Seek> {
    source: &'a mut R,
    spans: Vec<Span>,
    length: u64,
    position: u64,
}
impl<'a, R: Read + Seek> CheckedUdfSource<'a, R> {
    pub(crate) fn open(
        source: &'a mut R,
        image_bytes: u64,
        path: &str,
    ) -> Result<Self, UdfTreeError> {
        // Validate the full tree before trusting any extent. Fail if the file
        // overlaps another file, inode/metadata, or contains unsafe aliases.
        let tree = udf_tree::inspect(source, image_bytes)?;
        let entry = tree
            .file_paths
            .iter()
            .find(|p| !p.directory && p.path == path)
            .ok_or(UdfTreeError::Unsupported)?;
        if entry.file_bytes > MAX_FILE {
            return Err(UdfTreeError::Unsupported);
        }
        let vol = udf_structure::inspect(source, image_bytes)?;
        let mut current = vol
            .root_icb_lba
            .checked_sub(vol.partition_start_lba)
            .ok_or(UdfTreeError::Corrupt)?;
        for component in path.split('/') {
            let inode = udf_tree::checked_inode(source, &vol, image_bytes, current)?;
            if inode.kind != 4 {
                return Err(UdfTreeError::Corrupt);
            }
            let directory = udf_tree::checked_dir_bytes(source, &vol, image_bytes, &inode)?;
            let mut offset = 0usize;
            let mut next = None;
            while offset < directory.len() {
                if directory[offset] == 0 {
                    let boundary = ((offset / 2048) + 1) * 2048;
                    if directory[offset..directory.len().min(boundary)]
                        .iter()
                        .any(|&n| n != 0)
                    {
                        return Err(UdfTreeError::Corrupt);
                    }
                    offset = boundary;
                    continue;
                }
                let (lba, remaining) = udf_tree::logical_dir_sector(&inode.extents, offset)?;
                let (count, fid) =
                    udf_tree::checked_fid(&directory, offset, lba, vol.partition_number)?;
                if count > remaining {
                    return Err(UdfTreeError::Corrupt);
                }
                if let Some((name, block, _)) = fid
                    && name == component
                    && next.replace(block).is_some()
                {
                    return Err(UdfTreeError::Corrupt);
                }
                offset += count;
            }
            current = next.ok_or(UdfTreeError::Unsupported)?;
        }
        let content = udf_tree::checked_inode(source, &vol, image_bytes, current)?;
        if content.kind != 5 || content.size != entry.file_bytes {
            return Err(UdfTreeError::Corrupt);
        }
        let mut spans = Vec::new();
        if content.extents.len() > MAX_EXTENTS {
            return Err(UdfTreeError::Unsupported);
        }
        for e in content.extents {
            let bytes = u64::from(e.bytes);
            let first = partition_lba(
                e.block,
                vol.partition_start_lba,
                vol.partition_blocks,
                image_bytes,
            )?;
            let blocks = bytes.div_ceil(BLOCK);
            if u64::from(e.block) + blocks > u64::from(vol.partition_blocks)
                || first
                    .checked_add(blocks)
                    .and_then(|n| n.checked_mul(BLOCK))
                    .is_none_or(|n| n > image_bytes)
            {
                return Err(UdfTreeError::Corrupt);
            }
            spans.push(Span {
                absolute: first * BLOCK,
                bytes,
            });
        }
        Ok(Self {
            source,
            spans,
            length: entry.file_bytes,
            position: 0,
        })
    }
    pub(crate) fn len(&self) -> u64 {
        self.length
    }
}
impl<R: Read + Seek> Read for CheckedUdfSource<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.position == self.length || out.is_empty() {
            return Ok(0);
        }
        let mut within = self.position;
        for span in &self.spans {
            if within < span.bytes {
                let left = span.bytes - within;
                let len = (out.len() as u64).min(left) as usize;
                let position = span
                    .absolute
                    .checked_add(within)
                    .ok_or_else(|| fault("offset overflow"))?;
                self.source.seek(SeekFrom::Start(position))?;
                self.source.read_exact(&mut out[..len])?;
                self.position += len as u64;
                return Ok(len);
            }
            within -= span.bytes;
        }
        Err(fault("UDF source truncated or extent chain changed"))
    }
}
