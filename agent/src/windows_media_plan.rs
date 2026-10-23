//! Pure, read-only Windows installer *layout feasibility* planner.
//! It neither writes a GPT/FAT32 disk nor produces SWM files. Any candidate
//! becomes actionable only after a separately validated filesystem/writer gate.
use crate::windows_iso::WindowsIsoReport;
use serde::Serialize;

pub const FAT32_MAX_SINGLE_FILE: u64 = u32::MAX as u64;
// Split-WIM chunks must stay below FAT32's strict maximum; this is
// an illustrative split *target*, NOT a valid SWM encoder.
pub const PROPOSED_SPLIT_CHUNK: u64 = 3_800 * 1024 * 1024;
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsLayoutPlan {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub virtual_usb_builder_implemented: bool,
    pub windows_setup_boot_verified: bool,
    pub split_wim_implemented: bool,
    pub wim_resource_integrity_verified: bool,
    pub requested_firmware: &'static str,
    pub proposed_partition_scheme: &'static str,
    pub proposed_efi_filesystem: &'static str,
    pub install_payload_kind: &'static str,
    pub fat32_max_single_file_bytes: u64,
    pub install_payload_bytes: Option<u64>,
    pub requires_split_wim: bool,
    pub proposed_split_chunk_bytes: Option<u64>,
    pub fat32_file_fit_observed: Option<bool>,
    pub actionable: bool,
    pub state: &'static str,
}
pub fn plan(report: &WindowsIsoReport) -> WindowsLayoutPlan {
    let install = report.install_wim.as_ref().or(report.install_esd.as_ref());
    let kind = if report.install_wim.is_some() && report.install_esd.is_none() {
        "WIM"
    } else if report.install_esd.is_some() && report.install_wim.is_none() {
        "ESD"
    } else {
        "missing_or_ambiguous"
    };
    let bytes = install.map(|w| w.file_bytes);
    let requires_split = kind == "WIM" && bytes.is_some_and(|n| n > FAT32_MAX_SINGLE_FILE);
    let fit = bytes.map(|n| n <= FAT32_MAX_SINGLE_FILE);
    let complete = report.boot_wim.is_some()
        && kind != "missing_or_ambiguous"
        && report.x64_efi_loader_header_valid
        && report.setup_exe_observed
        && report.el_torito_uefi_catalog;
    let state = if report.udf_signature_observed {
        if !report.udf_filename_tree_verified {
            "udf_translation_and_file_tree_consistency_required"
        } else if report.udf_iso9660_file_listing_consistent != Some(true) {
            "udf_iso9660_namespace_conflict"
        } else {
            "udf_content_integrity_and_windows_boot_not_verified"
        }
    } else if !complete {
        "unqualified_windows_setup_structure"
    } else if requires_split {
        "split_wim_encoder_and_readback_required"
    } else if kind == "ESD" {
        "esd_resource_decoder_and_setup_boot_required"
    } else {
        "fat32_byte_length_candidate_requires_real_wim_and_setup_boot"
    };
    WindowsLayoutPlan {
        read_only: true,
        physical_write_authorized: false,
        virtual_usb_builder_implemented: false,
        windows_setup_boot_verified: false,
        split_wim_implemented: false,
        wim_resource_integrity_verified: false,
        requested_firmware: "uefi_x64_proposed_only",
        proposed_partition_scheme: "gpt_proposed_only",
        proposed_efi_filesystem: "fat32_proposed_only",
        install_payload_kind: kind,
        fat32_max_single_file_bytes: FAT32_MAX_SINGLE_FILE,
        install_payload_bytes: bytes,
        requires_split_wim: requires_split,
        proposed_split_chunk_bytes: if requires_split {
            Some(PROPOSED_SPLIT_CHUNK)
        } else {
            None
        },
        fat32_file_fit_observed: fit,
        actionable: false,
        state,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_iso::WimHeader;
    fn wim(file_bytes: u64) -> WimHeader {
        WimHeader {
            image_count: 1,
            format_version: 0x10d00,
            header_flags: 0,
            boot_index: 0,
            resources_verified: false,
            resource_ranges_bounded: true,
            solid_archive: false,
            part_number: 1,
            total_parts: 1,
            file_bytes,
        }
    }
    fn fake() -> WindowsIsoReport {
        WindowsIsoReport {
            read_only: true,
            physical_write_authorized: false,
            windows_setup_boot_verified: false,
            windows_version_verified: false,
            image_bytes: 6 * 1024 * 1024 * 1024,
            scanned_files: 12,
            observed_file_bytes: 5 * 1024 * 1024 * 1024,
            source_filesystem: "iso9660_primary_metadata_only",
            udf_translation_supported: false,
            udf_signature_observed: false,
            udf_structural_metadata_verified: false,
            udf_structure: None,
            udf_filename_tree_verified: false,
            udf_iso9660_file_listing_consistent: None,
            udf_tree: None,
            el_torito_uefi_catalog: true,
            x64_efi_loader_header_valid: true,
            setup_exe_observed: true,
            boot_wim: Some(wim(200_000_000)),
            install_wim: Some(wim(1024)),
            install_esd: None,
            installation_index_verified: false,
            wim_split_implemented: false,
            fat32_install_payload_compatible: None,
            virtual_cdrom_staging_eligible: false,
            recommended_handling: "not_qualified",
        }
    }
    #[test]
    fn exact_fat32_boundary_without_write_authority() {
        let mut r = fake();
        r.install_wim.as_mut().unwrap().file_bytes = FAT32_MAX_SINGLE_FILE;
        let candidate = plan(&r);
        assert_eq!(candidate.fat32_file_fit_observed, Some(true));
        assert!(!candidate.requires_split_wim && !candidate.actionable);
        assert!(!candidate.physical_write_authorized && !candidate.virtual_usb_builder_implemented);
        r.install_wim.as_mut().unwrap().file_bytes += 1;
        let above = plan(&r);
        assert_eq!(above.fat32_file_fit_observed, Some(false));
        assert!(above.requires_split_wim);
        assert_eq!(above.proposed_split_chunk_bytes, Some(PROPOSED_SPLIT_CHUNK));
        assert_eq!(above.state, "split_wim_encoder_and_readback_required");
        assert!(!above.split_wim_implemented && !above.windows_setup_boot_verified);
    }
    #[test]
    fn udf_independent_namespace_mismatch_blocks_windows_media() {
        let mut r = fake();
        r.udf_signature_observed = true;
        r.udf_filename_tree_verified = true;
        r.udf_iso9660_file_listing_consistent = Some(false);
        let p = plan(&r);
        assert_eq!(p.state, "udf_iso9660_namespace_conflict");
        assert!(!p.actionable && !p.virtual_usb_builder_implemented);
        r.udf_iso9660_file_listing_consistent = Some(true);
        assert_eq!(
            plan(&r).state,
            "udf_content_integrity_and_windows_boot_not_verified"
        );
        assert!(!plan(&r).windows_setup_boot_verified);
    }
    #[test]
    fn udf_and_esd_require_independent_qualification() {
        let mut r = fake();
        r.udf_signature_observed = true;
        assert_eq!(
            plan(&r).state,
            "udf_translation_and_file_tree_consistency_required"
        );
        r.udf_signature_observed = false;
        r.install_wim = None;
        r.install_esd = Some(wim(2_000_000));
        assert_eq!(
            plan(&r).state,
            "esd_resource_decoder_and_setup_boot_required"
        );
        r.install_wim = Some(wim(3_000_000));
        assert_eq!(plan(&r).install_payload_kind, "missing_or_ambiguous");
        assert!(!plan(&r).actionable);
    }
}
