//! ECMA-167/UDF descriptor-chain preflight for a *read-only optical image*.
//! This deliberately stops at root ICB metadata: no UDF FID traversal,
//! file-content extraction, hybrid media creation or installer-boot authority.
use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;

const BLOCK: u64 = 2048;
const MAX_IMAGE: u64 = 128 * 1024 * 1024 * 1024;
const MAX_VDS_SECTORS: u64 = 128;

#[derive(Debug, Error)]
pub enum UdfError {
    #[error("unsupported UDF partition map, descriptor version, or on-disc layout")]
    Unsupported,
    #[error("corrupt UDF descriptor tag, CRC, partition extent or root ICB")]
    Corrupt,
    #[error("UDF descriptor I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdfVolume {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub descriptor_chain_verified: bool,
    pub root_icb_tag_verified: bool,
    pub file_tree_traversal_supported: bool,
    pub installer_boot_verified: bool,
    pub logical_block_bytes: u32,
    pub partition_number: u16,
    pub partition_start_lba: u32,
    pub partition_blocks: u32,
    pub file_set_descriptor_lba: u32,
    pub root_icb_lba: u32,
}
pub(crate) fn u16_at(bytes: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([bytes[pos], bytes[pos + 1]])
}
pub(crate) fn u32_at(bytes: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap())
}
pub(crate) fn sector<R: Read + Seek>(
    r: &mut R,
    image_bytes: u64,
    lba: u64,
) -> Result<[u8; 2048], UdfError> {
    let start = lba.checked_mul(BLOCK).ok_or(UdfError::Corrupt)?;
    if start.checked_add(BLOCK).is_none_or(|end| end > image_bytes) {
        return Err(UdfError::Corrupt);
    }
    let mut data = [0u8; 2048];
    r.seek(SeekFrom::Start(start))?;
    r.read_exact(&mut data)?;
    Ok(data)
}
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                crc.wrapping_shl(1) ^ 0x1021
            } else {
                crc.wrapping_shl(1)
            };
        }
    }
    crc
}
pub(crate) fn tag(data: &[u8; 2048], lba: u64, wanted: u16) -> Result<(), UdfError> {
    if u16_at(data, 0) != wanted
        || !matches!(u16_at(data, 2), 2 | 3)
        || u32_at(data, 12) as u64 != lba
        || data[5] != 0
    {
        return Err(UdfError::Corrupt);
    }
    let checksum = data[..16]
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
        .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte));
    let crc_bytes = u16_at(data, 10) as usize;
    // A CRC that omits security-critical fields is not sufficient even when
    // the checksum and shortened CRC are internally consistent.
    let required_crc = match wanted {
        2 | 5 | 8 | 256 => 496,
        6 => 430,   // type-1 partition map ends at byte 446
        261 => 160, // File Entry variable attributes checked below
        _ => 32,
    };
    if checksum != data[4]
        || !(required_crc..=2048 - 16).contains(&crc_bytes)
        || crc16(&data[16..16 + crc_bytes]) != u16_at(data, 8)
    {
        return Err(UdfError::Corrupt);
    }
    Ok(())
}
pub(crate) fn partition_lba(
    block: u32,
    partition_start: u32,
    partition_blocks: u32,
    image_bytes: u64,
) -> Result<u64, UdfError> {
    if block >= partition_blocks {
        return Err(UdfError::Corrupt);
    }
    let lba = u64::from(partition_start)
        .checked_add(u64::from(block))
        .ok_or(UdfError::Corrupt)?;
    if lba
        .checked_add(1)
        .and_then(|n| n.checked_mul(BLOCK))
        .is_none_or(|n| n > image_bytes)
    {
        return Err(UdfError::Corrupt);
    }
    Ok(lba)
}

/// Validate descriptor tags, anchor, main VDS, partition map, File Set
/// Descriptor and root File Entry. No file paths or bytes are returned.
pub fn inspect<R: Read + Seek>(input: &mut R, image_bytes: u64) -> Result<UdfVolume, UdfError> {
    if !(257 * BLOCK..=MAX_IMAGE).contains(&image_bytes) || !image_bytes.is_multiple_of(BLOCK) {
        return Err(UdfError::Unsupported);
    }
    let anchor = sector(input, image_bytes, 256)?;
    tag(&anchor, 256, 2)?;
    let vds_bytes = u64::from(u32_at(&anchor, 16));
    let vds_start = u64::from(u32_at(&anchor, 20));
    if vds_bytes == 0
        || vds_bytes % BLOCK != 0
        || vds_bytes / BLOCK > MAX_VDS_SECTORS
        || vds_start < 16
        || vds_start
            .checked_add(vds_bytes / BLOCK)
            .and_then(|end| end.checked_mul(BLOCK))
            .is_none_or(|bytes| bytes > image_bytes)
    {
        return Err(UdfError::Corrupt);
    }
    if vds_start <= 256 && vds_start + vds_bytes / BLOCK > 256 {
        return Err(UdfError::Corrupt);
    }
    let mut partition: Option<(u16, u32, u32)> = None;
    let mut lvd: Option<[u8; 2048]> = None;
    let mut terminated = false;
    for n in 0..vds_bytes / BLOCK {
        let lba = vds_start + n;
        let bytes = sector(input, image_bytes, lba)?;
        let kind = u16_at(&bytes, 0);
        if kind == 0 {
            return Err(UdfError::Corrupt);
        }
        if !matches!(kind, 1..=9) {
            return Err(UdfError::Unsupported);
        }
        tag(&bytes, lba, kind)?;
        if kind == 5 {
            if partition.is_some() {
                return Err(UdfError::Unsupported);
            }
            let number = u16_at(&bytes, 22);
            let start = u32_at(&bytes, 188);
            let count = u32_at(&bytes, 192);
            if count == 0
                || u64::from(start)
                    .checked_add(u64::from(count))
                    .and_then(|n| n.checked_mul(BLOCK))
                    .is_none_or(|n| n > image_bytes)
            {
                return Err(UdfError::Corrupt);
            }
            partition = Some((number, start, count));
        } else if kind == 6 {
            if lvd.replace(bytes).is_some() {
                return Err(UdfError::Unsupported);
            }
        } else if kind == 8 {
            terminated = true;
            break;
        }
    }
    if !terminated {
        return Err(UdfError::Corrupt);
    }
    let (part_num, start, count) = partition.ok_or(UdfError::Unsupported)?;
    let logical = lvd.ok_or(UdfError::Unsupported)?;
    if u32_at(&logical, 212) != 2048
        || u32_at(&logical, 264) != 6
        || u32_at(&logical, 268) != 1
        || logical[440] != 1
        || logical[441] != 6
        || u16_at(&logical, 442) != 1
        || u16_at(&logical, 444) != part_num
        || !logical[217..248]
            .windows(19)
            .any(|w| w == b"*OSTA UDF Compliant")
    {
        return Err(UdfError::Unsupported);
    }
    // LongAd in LVD contents use at offset 248: byte extent size,
    // block number within partition, partition number. Only one logical block.
    let fsd_bytes = u32_at(&logical, 248) & 0x3fff_ffff;
    let fsd_block = u32_at(&logical, 252);
    let fsd_part = u16_at(&logical, 256);
    if fsd_part != part_num || fsd_bytes != 2048 {
        return Err(UdfError::Unsupported);
    }
    let fsd_lba = partition_lba(fsd_block, start, count, image_bytes)?;
    let fsd = sector(input, image_bytes, fsd_lba)?;
    tag(&fsd, u64::from(fsd_block), 256)?;
    let root_bytes = u32_at(&fsd, 400) & 0x3fff_ffff;
    let root_block = u32_at(&fsd, 404);
    let root_part = u16_at(&fsd, 408);
    if root_part != part_num || root_bytes != 2048 {
        return Err(UdfError::Unsupported);
    }
    let root_lba = partition_lba(root_block, start, count, image_bytes)?;
    let root = sector(input, image_bytes, root_lba)?;
    // A File Entry tag alone doesn't prove that the directory contents
    // can be safely traversed. Only recognize a short/long allocation header.
    tag(&root, u64::from(root_block), 261)?;
    if root[27] != 4 || u16_at(&root, 34) & 7 > 1 {
        return Err(UdfError::Unsupported);
    }
    let ea_len = u32_at(&root, 168) as usize;
    let ad_len = u32_at(&root, 172) as usize;
    if (u16_at(&root, 10) as usize) < 160usize.saturating_add(ea_len).saturating_add(ad_len)
        || !ea_len.is_multiple_of(4)
        || 176usize
            .checked_add(ea_len)
            .and_then(|n| n.checked_add(ad_len))
            .is_none_or(|n| n > root.len())
    {
        return Err(UdfError::Corrupt);
    }
    Ok(UdfVolume {
        read_only: true,
        physical_write_authorized: false,
        descriptor_chain_verified: true,
        root_icb_tag_verified: true,
        file_tree_traversal_supported: false,
        installer_boot_verified: false,
        logical_block_bytes: 2048,
        partition_number: part_num,
        partition_start_lba: start,
        partition_blocks: count,
        file_set_descriptor_lba: fsd_lba as u32,
        root_icb_lba: root_lba as u32,
    })
}
#[cfg(test)]
#[path = "udf_structure_tests.rs"]
mod tests;
