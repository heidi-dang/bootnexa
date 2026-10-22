//! Bounded ISO9660 / UDF Volume Recognition / El Torito classifier.
//! Reads at most 64 descriptor sectors + 1 boot catalog + initial MBR.
//! It never extracts paths, executes images or accepts a disk-writing target.
use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;
const SECTOR: u64 = 2048;
const MAX_DESCRIPTORS: u64 = 64;
const MAX_IMAGE: u64 = 128 * 1024 * 1024 * 1024;
#[derive(Debug, Error)]
pub enum IsoError {
    #[error("input is too small, too large, or unsupported")]
    Unsupported,
    #[error("ISO descriptor or boot catalog is corrupted")]
    Corrupt,
    #[error("image read error")]
    Io(#[from] std::io::Error),
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IsoReport {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub iso9660: bool,
    pub udf_recognition: bool,
    pub el_torito: bool,
    pub bios_catalog_entry: bool,
    pub uefi_catalog_entry: bool,
    pub hybrid_mbr_candidate: bool,
    pub descriptor_count: u32,
    pub volume_label: Option<String>,
    pub recommended_handling: String,
    pub boot_execution_verified: bool,
}
fn read_sector<R: Read + Seek>(r: &mut R, lba: u64) -> Result<[u8; 2048], IsoError> {
    let mut sector = [0u8; 2048];
    r.seek(SeekFrom::Start(
        lba.checked_mul(SECTOR).ok_or(IsoError::Corrupt)?,
    ))?;
    r.read_exact(&mut sector)?;
    Ok(sector)
}
fn catalog_flags(cat: &[u8; 2048]) -> Result<(bool, bool), IsoError> {
    if cat[0] != 1 || cat[30] != 0x55 || cat[31] != 0xaa {
        return Err(IsoError::Corrupt);
    }
    let checksum = cat[..32].as_chunks::<2>().0.iter().fold(0u16, |sum, b| {
        sum.wrapping_add(u16::from_le_bytes([b[0], b[1]]))
    });
    if checksum != 0 {
        return Err(IsoError::Corrupt);
    }
    let mut bios = false;
    let mut uefi = false;
    let platform = cat[1];
    if cat[32] == 0x88 {
        if platform == 0xef {
            uefi = true;
        } else if platform == 0 {
            bios = true;
        } else {
            return Err(IsoError::Corrupt);
        }
    } else if cat[32] != 0 {
        return Err(IsoError::Corrupt);
    }
    let mut index = 64;
    let mut sections = 0;
    while index + 64 <= cat.len() && sections < 16 {
        let marker = cat[index];
        if marker == 0 {
            break;
        }
        if marker != 0x90 && marker != 0x91 {
            return Err(IsoError::Corrupt);
        }
        let section_platform = cat[index + 1];
        let entry_count = u16::from_le_bytes([cat[index + 2], cat[index + 3]]) as usize;
        if entry_count == 0 || entry_count > 32 || index + 32 + 32 * entry_count > cat.len() {
            return Err(IsoError::Corrupt);
        }
        for n in 0..entry_count {
            let entry = index + 32 + 32 * n;
            if cat[entry] == 0x88 {
                match section_platform {
                    0 => bios = true,
                    0xef => uefi = true,
                    _ => return Err(IsoError::Corrupt),
                }
            } else if cat[entry] != 0 {
                return Err(IsoError::Corrupt);
            }
        }
        index += 32 + entry_count * 32;
        sections += 1;
        if marker == 0x91 {
            break;
        }
    }
    Ok((bios, uefi))
}
pub fn inspect<R: Read + Seek>(r: &mut R, length: u64) -> Result<IsoReport, IsoError> {
    if !(17 * SECTOR..=MAX_IMAGE).contains(&length) {
        return Err(IsoError::Unsupported);
    }
    let mut head = [0u8; 512];
    r.seek(SeekFrom::Start(0))?;
    r.read_exact(&mut head)?;
    let hybrid = head[510..] == [0x55, 0xaa]
        && (0..4).any(|n| {
            head[446 + n * 16 + 4] != 0
                && head[446 + n * 16 + 12..446 + n * 16 + 16]
                    .iter()
                    .any(|x| *x != 0)
        });
    let mut found_iso = false;
    let mut udf = false;
    let mut label = None;
    let mut count = 0;
    let mut catalog_lba = None;
    let mut terminator = false;
    for i in 0..MAX_DESCRIPTORS {
        let lba = 16 + i;
        if (lba + 1) * SECTOR > length {
            break;
        }
        let sector = read_sector(r, lba)?;
        let signature = &sector[1..6];
        if signature == b"CD001" {
            if sector[6] != 1 {
                return Err(IsoError::Corrupt);
            }
            count += 1;
            match sector[0] {
                0 if &sector[7..30] == b"EL TORITO SPECIFICATION" => {
                    let location = u32::from_le_bytes(sector[71..75].try_into().unwrap()) as u64;
                    if location == 0 || (location + 1) * SECTOR > length {
                        return Err(IsoError::Corrupt);
                    }
                    if catalog_lba.replace(location).is_some() {
                        return Err(IsoError::Corrupt);
                    }
                }
                1 => {
                    if found_iso {
                        return Err(IsoError::Corrupt);
                    }
                    found_iso = true;
                    let name = &sector[40..72];
                    if name
                        .iter()
                        .any(|b| !b.is_ascii() || (*b < 0x20 && *b != b' '))
                    {
                        return Err(IsoError::Corrupt);
                    }
                    let cleaned = String::from_utf8_lossy(name).trim().to_string();
                    if !cleaned.is_empty() {
                        label = Some(cleaned);
                    }
                }
                255 => {
                    terminator = true;
                    break;
                }
                _ => {}
            }
        } else if signature == b"NSR02" || signature == b"NSR03" {
            udf = true;
            count += 1;
        } else if signature == b"BEA01" || signature == b"TEA01" {
            count += 1;
        } else {
            return Err(IsoError::Corrupt);
        }
    }
    if !found_iso && !udf {
        return Err(IsoError::Unsupported);
    }
    if found_iso && !terminator && !udf {
        return Err(IsoError::Corrupt);
    }
    let (bios, uefi) = if let Some(lba) = catalog_lba {
        catalog_flags(&read_sector(r, lba)?)?
    } else {
        (false, false)
    };
    // Hybrid is only a *candidate*. Actual partition overlap and bootability
    // must be checked by a separate validated planner/virtual boot stage.
    let strategy = if hybrid && (bios || uefi) {
        "hybrid_candidate_inspection_only"
    } else {
        "inspection_only_no_extraction"
    };
    Ok(IsoReport {
        read_only: true,
        physical_write_authorized: false,
        iso9660: found_iso,
        udf_recognition: udf,
        el_torito: catalog_lba.is_some(),
        bios_catalog_entry: bios,
        uefi_catalog_entry: uefi,
        hybrid_mbr_candidate: hybrid,
        descriptor_count: count,
        volume_label: label,
        recommended_handling: strategy.into(),
        boot_execution_verified: false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn make_iso(with_boot: bool) -> Vec<u8> {
        let mut disk = vec![0u8; 64 * 2048];
        let pvd = 16 * 2048;
        disk[pvd] = 1;
        disk[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        disk[pvd + 6] = 1;
        disk[pvd + 40..pvd + 72].fill(b' ');
        disk[pvd + 40..pvd + 49].copy_from_slice(b"BOOTNEXA ");
        let mut next = 17;
        if with_boot {
            let boot = 17 * 2048;
            disk[boot] = 0;
            disk[boot + 1..boot + 6].copy_from_slice(b"CD001");
            disk[boot + 6] = 1;
            disk[boot + 7..boot + 30].copy_from_slice(b"EL TORITO SPECIFICATION");
            disk[boot + 71..boot + 75].copy_from_slice(&30u32.to_le_bytes());
            let catalog = 30 * 2048;
            disk[catalog] = 1;
            disk[catalog + 1] = 0xef;
            disk[catalog + 30] = 0x55;
            disk[catalog + 31] = 0xaa;
            let sum = disk[catalog..catalog + 32]
                .as_chunks::<2>()
                .0
                .iter()
                .fold(0u16, |s, b| {
                    s.wrapping_add(u16::from_le_bytes([b[0], b[1]]))
                });
            let correction = 0u16.wrapping_sub(sum);
            disk[catalog + 28..catalog + 30].copy_from_slice(&correction.to_le_bytes());
            disk[catalog + 32] = 0x88;
            next = 18;
        }
        let term = next * 2048;
        disk[term] = 255;
        disk[term + 1..term + 6].copy_from_slice(b"CD001");
        disk[term + 6] = 1;
        disk
    }
    #[test]
    fn pvd_and_uefi_catalog_found() {
        let data = make_iso(true);
        let x = inspect(&mut Cursor::new(&data), data.len() as u64).unwrap();
        assert_eq!(x.volume_label.as_deref(), Some("BOOTNEXA"));
        assert!(x.iso9660 && x.el_torito && x.uefi_catalog_entry);
        assert!(!x.bios_catalog_entry && !x.physical_write_authorized);
    }
    #[test]
    fn no_catalog_is_not_bootable() {
        let data = make_iso(false);
        let x = inspect(&mut Cursor::new(&data), data.len() as u64).unwrap();
        assert!(!x.el_torito && !x.uefi_catalog_entry);
    }
    #[test]
    fn malicious_catalog_and_descriptors_rejected() {
        for mutate in 0..6 {
            let mut data = make_iso(true);
            match mutate {
                0 => data[16 * 2048 + 1] = 0,
                1 => data[16 * 2048 + 6] = 9,
                2 => data[17 * 2048 + 71..17 * 2048 + 75].copy_from_slice(&u32::MAX.to_le_bytes()),
                3 => data[30 * 2048 + 30] = 0,
                4 => data[30 * 2048 + 28] ^= 1,
                5 => data[16 * 2048 + 40] = 0xff,
                _ => unreachable!(),
            };
            assert!(
                inspect(&mut Cursor::new(&data), data.len() as u64).is_err(),
                "mutation {mutate}"
            );
        }
    }
    #[test]
    fn huge_truncated_or_random_image_does_not_allocate() {
        let data = make_iso(false);
        assert!(inspect(&mut Cursor::new(&data), u64::MAX).is_err());
        assert!(inspect(&mut Cursor::new(&data), 1000).is_err());
        assert!(inspect(&mut Cursor::new(vec![7u8; data.len()]), data.len() as u64).is_err());
    }
}
