#!/usr/bin/env python3
"""Read-only official ISO manifest -> combined SWM virtual-profile feasibility.

This consumes a *snapshot*, never authority: it does NOT access an ISO, fetch
Microsoft digests, verify WIM resources, create SWMs or write a virtual disk.
A suitable report is only a capacity study. Live provenance verification,
source-before/after hashing, WIM splitting and WinPE guest boot are separate.
"""
import argparse
import json
from pathlib import Path
import sys
import windows_installer_layout_plan as layout

GIB = layout.GIB
MAX_EXTRA_BYTES = 2*GIB
MAX_EXTRA_FILE = GIB
MAX_SPLIT_WIM_BYTES = 16*GIB
MAX_FILE_COUNT = 4096


def assess(doc, disk_gib, digest=None):
    proposal = layout.estimate_layout(doc, disk_gib, digest)
    canonical, _, kind = layout.validate_manifest(doc)
    installed = canonical[f"sources/install.{kind.lower()}"]
    others = [v for k, v in canonical.items()
              if k != f"sources/install.{kind.lower()}"]
    count = len(others)
    total = sum(file["bytes"] for file in others)
    max_extra = max((file["bytes"] for file in others), default=0)
    blockers = []
    if kind != "WIM":
        blockers.append("combined_swm_profile_does_not_handle_install_esd")
    if installed["bytes"] > MAX_SPLIT_WIM_BYTES:
        blockers.append("source_wim_exceeds_16gib_split_payload_limit")
    if count < 4 or count > MAX_FILE_COUNT:
        blockers.append("non_install_file_count_exceeds_combined_stream_policy")
    if max_extra > MAX_EXTRA_FILE:
        blockers.append("non_install_file_exceeds_1gib_stream_policy")
    if total > MAX_EXTRA_BYTES:
        blockers.append("non_install_files_exceed_2gib_stream_policy")
    if disk_gib < 8:
        blockers.append("combined_profile_requires_8gib_minimum")
    if "fat32_payload_partition_capacity_exceeded" in proposal["blockers"]:
        blockers.append("fat32_partition_capacity_exceeded")
    if "efi_partition_capacity_exceeded" in proposal["blockers"]:
        blockers.append("efi_partition_capacity_exceeded")
    if "other_iso_file_exceeds_fat32_single_file_limit" in proposal["blockers"]:
        blockers.append("non_install_fat32_single_file_limit_exceeded")
    # The nominal FAT32 payload has to account for actual split metadata,
    # all non-install file bytes and conservative occupancy; no fabricated
    # split-part count or checksum is an executable contract.
    payload_capacity = proposal["proposedPartitionLayout"]["payload"]["bytes"]
    payload_other = sum(v["bytes"] for v in others
                        if not v["path"].casefold().startswith("efi/"))
    projected = installed["bytes"] + payload_other
    projected += projected//4 + 192*layout.MIB
    if projected > payload_capacity:
        blockers.append("combined_swm_and_file_payload_capacity_exceeded")
    # These are mandatory even when all geometric feasibility checks pass.
    outstanding = [
        "manifest_is_untrusted_snapshot_not_current_publisher_attestation",
        "live_iso_checksum_and_per_file_reverification_required",
        "actual_wimlib_split_swm_sha_receipt_required",
        "boot_wim_and_efi_pe_execution_unverified",
        "complete_source_iso_tree_stream_and_readback_unverified",
        "genuine_windows_setup_guest_boot_unverified",
        "real_usb_writing_prohibited",
    ]
    return {
        "schema": "bootnexa-official-media-combined-compatibility-gate-v1",
        "readOnly": True,
        "virtualOnly": True,
        "manifestAssertionsTrusted": False,
        "physicalWriteAuthorized": False,
        "windowsSetupBootVerified": False,
        "installerCompatibleVerified": False,
        "completeVirtualInstallerProduced": False,
        "officialMicrosoftIsoProcessed": False,
        "safeToExecute": False,
        "installationPayloadKind": kind,
        "requiresVerifiedWimSplit": kind == "WIM",
        "proposedDiskGiB": disk_gib,
        "nonInstallFileCount": count,
        "nonInstallBytes": total,
        "largestNonInstallFileBytes": max_extra,
        "sourceWimOrEsdBytes": installed["bytes"],
        "syntheticCombinedProfileImplemented": True,
        "syntheticCombinedProfileCapacityFeasible": not blockers,
        "feasibilityBlockers": blockers,
        "unverifiedAcceptanceGates": outstanding,
        "sourceManifestSha256": digest,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--disk-gib", type=int, required=True)
    args = parser.parse_args()
    try:
        manifest, sha = layout.read_manifest(args.manifest)
        report = assess(manifest, args.disk_gib, sha)
    except (layout.Refused, ValueError, OSError, TypeError, KeyError) as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
