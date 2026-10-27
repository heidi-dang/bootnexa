#!/usr/bin/env python3
"""Read-only, fail-closed host/source admission for genuine Windows ISO tests.

Never downloads an ISO, extracts any media, launches QEMU, or creates disk
images. Only a live Microsoft.com reference can qualify the official-media
source. Machine readiness does not establish actual Windows Setup boot.
"""
from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import windows_iso_publisher_manifest as source_gate

GIB=1024**3
MIN_FREE=20*GIB
BINARY=Path("agent/target/release/bootnexa-media")
DEPENDENCIES=("7z","wimlib-imagex","qemu-system-x86_64")
OVMF_SETS=(("OVMF_CODE_4M.fd","OVMF_VARS_4M.fd"),
           ("OVMF_CODE.fd","OVMF_VARS.fd"))
OVMF_DIRS=(Path("/usr/share/OVMF"),Path("/usr/share/ovmf"))


def firmware_available(dirs=OVMF_DIRS):
    for root in dirs:
        for code,variables in OVMF_SETS:
            a,b=root/code,root/variables
            try:
                if all(stat.S_ISREG(p.lstat().st_mode) for p in (a,b)):
                    return True
            except (FileNotFoundError,OSError):
                continue
    return False


def native_combined_capability(executable):
    """Prove actual binary supports BNXI0002, not merely that a file exists."""
    try:
        child=subprocess.run([str(executable),"capabilities"],
                             stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        if child.returncode or len(child.stdout)>8192 or len(child.stderr)>8192:
            return False
        value=json.loads(child.stdout)
        return (isinstance(value,dict)
                and value.get("schema")=="bootnexa-native-virtual-capabilities-v1"
                and value.get("combinedIsoStreamMagic")=="BNXI0002"
                and value.get("supportsCombinedIsoSwmStream") is True
                and value.get("virtualOnly") is True
                and value.get("requiresExperimentalVirtualConfirmation") is True
                and value.get("physicalWriteAuthorized") is False
                and value.get("persistentDiskImageProduced") is False
                and value.get("officialWindowsSetupBootVerified") is False)
    except (OSError,ValueError,subprocess.SubprocessError):
        return False


def inspect(iso,locale,scratch_parent, *,get_reference=None,
            find_executable=shutil.which,firmware_check=firmware_available,
            minimum_iso_bytes=source_gate.MIN_OFFICIAL_ISO,
            native_binary=BINARY,capability_probe=native_combined_capability):
    if locale not in source_gate.SUPPORTED_LOCALES:
        raise source_gate.Rejected("unsupported Windows ISO locale")
    # Injection exists only for synthetic unit tests; the real CLI never
    # exposes this parameter. Only our default fetch is live attestation.
    is_live=get_reference is None
    ref_fn=get_reference or source_gate.fetch_publisher_reference
    flags={name:bool(find_executable(name)) for name in DEPENDENCIES}
    try:
        binary=source_gate.safe_regular(native_binary)
        present=bool(binary.is_file() and os.access(binary,os.X_OK))
        native=bool(present and capability_probe(binary))
        binary_sha=source_gate.file_sha(binary,64*1024*1024)[1] if present else None
    except (OSError,source_gate.Rejected):
        present=False
        native=False
        binary_sha=None
    space=None
    scratch_valid=False
    try:
        scratch=source_gate.safe_parent(scratch_parent)
        info=os.statvfs(scratch)
        space=info.f_bavail*info.f_frsize
        scratch_valid=True
    except (OSError,source_gate.Rejected):
        pass
    source_present=False
    source_bytes=None
    source_sha=None
    source_exact_match=False
    source_read_error=False
    if iso is not None:
        try:
            file=source_gate.safe_regular(iso)
            source_bytes,source_sha=source_gate.file_sha(file,source_gate.MAX_ISO)
            source_present=minimum_iso_bytes<=source_bytes
        except (OSError,source_gate.Rejected):
            source_read_error=True
    publisher=None
    reference_sha=None
    error=None
    try:
        ref=ref_fn(locale)
        digest=ref.get("referenceSha256") if isinstance(ref,dict) else None
        if not isinstance(digest,str) or not re.fullmatch("[0-9a-f]{64}",digest):
            raise source_gate.Rejected("publisher checksum response is invalid")
        if is_live and (ref.get("sourceUrl")!=source_gate.OFFICIAL_URL
                        or ref.get("locale")!=locale):
            raise source_gate.Rejected("publisher checksum origin or locale mismatch")
        reference_sha=digest
        publisher=True
        source_exact_match=bool(source_present and source_sha==reference_sha)
    except (OSError,ValueError,TypeError) as exc:
        publisher=False
        error=type(exc).__name__
    blockers=[]
    if not scratch_valid:
        blockers.append("scratch_parent_missing_or_unsafe")
    elif space is None or space<MIN_FREE:
        blockers.append("scratch_preflight_free_space_below_20gib_floor")
    if not flags["7z"]:
        blockers.append("seven_zip_decoder_unavailable")
    if not flags["wimlib-imagex"]:
        blockers.append("wimlib_verification_unavailable")
    if not present:
        blockers.append("release_native_media_cli_unavailable")
    elif not native:
        blockers.append("release_native_cli_missing_current_combined_capability")
    if iso is None:
        blockers.append("operator_supplied_authentic_iso_missing")
    elif source_read_error or not source_present:
        blockers.append("iso_missing_unsafe_or_outside_size_budget")
    if not publisher:
        blockers.append("current_microsoft_checksum_unavailable")
    elif source_present and not source_exact_match:
        blockers.append("iso_sha256_does_not_match_live_microsoft_reference")
    if not is_live:
        blockers.append("test_reference_is_not_live_microsoft_provenance")
    data_ready=not blockers
    guest_blockers=[]
    if not flags["qemu-system-x86_64"]:
        guest_blockers.append("qemu_guest_execution_unavailable")
    if not firmware_check():
        guest_blockers.append("ovmf_firmware_unavailable")
    return {
        "schema":"bootnexa-genuine-media-readiness-v1",
        "checkedUtc":datetime.now(timezone.utc).isoformat(),
        "readOnly":True,
        "offlineMediaCreationAttempted":False,
        "microsoftIsoDownloaded":False,
        "hostTooling":flags,
        "nativeReleaseCliPresent":present,
        "nativeCombinedCapabilityVerified":native,
        "nativeReleaseCliSha256":binary_sha,
        "ovmfFirmwarePresent":not("ovmf_firmware_unavailable" in guest_blockers),
        "scratchParentValid":scratch_valid,
        "scratchAvailableBytes":space,
        "minimumInitialScratchBytes":MIN_FREE,
        "isoSourcePresentAndSizeAllowed":source_present,
        "isoSourceBytes":source_bytes,
        "isoSourceSha256":source_sha,
        "publisherReferenceFromLiveMicrosoft":is_live and publisher,
        "publisherReferenceAvailable":publisher,
        "publisherReferenceErrorType":error,
        "publisherReferenceSha256":reference_sha,
        "isoSha256MatchedReference":source_exact_match,
        "dataTransferReadyForOperator":data_ready,
        "guestEvidenceHostReady":not guest_blockers,
        "guestCaptureReadyForOperator":data_ready and not guest_blockers,
        "dataTransferBlockers":blockers,
        "guestEvidenceBlockers":guest_blockers,
        "actualSourceBoundStagingExecuted":False,
        "windowsSetupBootVerified":False,
        "genuineWindowsSetupObserved":False,
        "installerCompatibleVerified":False,
        "physicalWriteAuthorized":False,
        "persistentDiskImageProduced":False,
        "manualSetupReviewRequired":True,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso",type=Path,
                        help="operator-acquired Windows ISO, optional for host-only readiness")
    parser.add_argument("--locale",choices=source_gate.SUPPORTED_LOCALES,
                        default="English International 64-bit")
    parser.add_argument("--scratch-parent",type=Path,required=True)
    args=parser.parse_args()
    try:
        result=inspect(args.iso,args.locale,args.scratch_parent)
    except (ValueError,OSError) as exc:
        print(f"DENIED: {exc}",file=sys.stderr)
        return 1
    print(json.dumps(result,indent=2))
    # Zero is possible only when authentic bytes AND the live reference agree
    # and tools/scratch are available. This never grants physical writes.
    return 0 if result["dataTransferReadyForOperator"] else 2


if __name__=="__main__":
    raise SystemExit(main())
