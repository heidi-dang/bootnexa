#!/usr/bin/env python3
"""Dry-run Windows virtual installer partition/file placement planner.

Consumes PR39's *untrusted*, locally stored ISO checksum/manifest receipt.
All sizes are capacity proposals; no filesystem creation, ISO extraction,
WIM conversion, guest VM, exported disk, or physical device operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

import windows_iso_publisher_manifest as source_gate

GIB=1024**3
MIB=1024**2
MAX_FAT32_FILE=2**32-1
SWM_TARGET=3800*MIB  # proposed only; wimlib may create different actual sizes
MIN_GIB=1
MAX_GIB=24
EFI_MIB=256
EFI_HEADROOM=16*MIB
PAYLOAD_HEADROOM=64*MIB
MAX_PLAN_JSON=8*MIB
MAX_PATH_SEGMENTS=16
MAX_FILES=4096
MIN_FILE_OVERHEAD=32*1024
GPT_ALIGNMENT=2048*512
GPT_BACKUP=34*512
OFFICIAL_SCHEMA="bootnexa-official-iso-manifest-v1"
MANDATORY={"EFI/BOOT/BOOTX64.EFI","SOURCES/BOOT.WIM","SETUP.EXE"}
INSTALL_KINDS={"SOURCES/INSTALL.WIM":"WIM","SOURCES/INSTALL.ESD":"ESD"}
FAT_FORBIDDEN=set('<>:"\\|?*')
WINDOWS_DOS_RESERVED={
    "CON","PRN","AUX","NUL",
    *(f"COM{i}" for i in range(1,10)),
    *(f"LPT{i}" for i in range(1,10)),
}

class Refused(ValueError):
    pass

def assert_sha(value):
    if not isinstance(value,str) or not re.fullmatch(r"[a-fA-F0-9]{64}",value):
        raise Refused("invalid SHA-256 in manifest")
    return value.lower()

def safe_fat_path(value):
    try:
        source_gate.checked_path(value)
    except (ValueError,TypeError) as exc:
        raise Refused("unsafe or ambiguous source path") from exc
    if value.casefold().startswith("[boot]/"):
        raise Refused("7-Zip synthetic El Torito boot view is not a filesystem file")
    for part in value.split("/"):
        if part.endswith((" ",".")) or part[0]==" " or set(part)&FAT_FORBIDDEN:
            raise Refused("file name incompatible with FAT32 long-file naming")
        if part.upper().split(".")[0] in WINDOWS_DOS_RESERVED:
            raise Refused("Windows reserved device name forbidden")
    return value

def read_manifest(path):
    path=Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise Refused("manifest must be a regular file, not symlink or device")
    if path.stat().st_size>MAX_PLAN_JSON:
        raise Refused("manifest JSON exceeds 8 MiB")
    # This is a planning snapshot, NOT an immutable/signed provenance proof.
    with path.open("rb") as file:
        blob=file.read(MAX_PLAN_JSON+1)
    if len(blob)>MAX_PLAN_JSON:
        raise Refused("manifest grew while reading")
    try:
        data=json.loads(blob)
    except (ValueError,UnicodeError) as exc:
        raise Refused("malformed manifest JSON") from exc
    return data,hashlib.sha256(blob).hexdigest()

def validate_manifest(doc):
    if not isinstance(doc,dict) or doc.get("schema")!=OFFICIAL_SCHEMA:
        raise Refused("not a Bootnexa official-media manifest schema")
    if doc.get("publisherChecksumMatched") is not True or \
       doc.get("isoSourceUnchanged") is not True or \
       doc.get("allListedFilesIndependentlyHashed") is not True:
        raise Refused("manifest does not assert successful full source verification")
    if doc.get("windowsSetupBootVerified") is not False or \
       doc.get("physicalWriteAuthorized") is not False or \
       doc.get("installerCompatibleVerified") is not False:
        raise Refused("manifest contains false or unsafe readiness claims")
    observed=assert_sha(doc.get("sourceSha256"))
    source_bytes=doc.get("sourceBytes")
    if type(source_bytes) is not int or not 512*MIB<=source_bytes<=24*GIB:
        raise Refused("source ISO length outside official-media intake budget")
    ref=doc.get("publisherChecksumReference")
    if not isinstance(ref,dict) or \
       ref.get("sourceUrl")!=source_gate.OFFICIAL_URL or \
       ref.get("locale") not in source_gate.SUPPORTED_LOCALES or \
       assert_sha(ref.get("referenceSha256"))!=observed:
        raise Refused("manifest lacks expected Microsoft URL/locale/SHA binding")
    files=doc.get("files")
    if not isinstance(files,list) or not 1<=len(files)<=MAX_FILES or \
       type(doc.get("listedFileCount")) is not int or \
       doc.get("listedFileCount")!=len(files):
        raise Refused("manifest file count missing, inconsistent or excessive")
    canonical={}
    total=0
    for item in files:
        if not isinstance(item,dict) or set(item)!={"path","bytes","sha256"}:
            raise Refused("invalid file record keys")
        path=safe_fat_path(item["path"])
        folded=path.casefold()
        if folded in canonical:
            raise Refused("FAT32 case-insensitive destination collision")
        length=item["bytes"]
        if type(length) is not int or length<0 or length>source_gate.MAX_FILE:
            raise Refused("invalid source file size")
        total+=length
        if total>source_gate.MAX_SUM:
            raise Refused("ISO manifest exceeds aggregate file budget")
        canonical[folded]={"path":path,"bytes":length,
                           "sha256":assert_sha(item["sha256"])}
    for folded in canonical:
        components=folded.split("/")
        if any("/".join(components[:i]) in canonical
               for i in range(1,len(components))):
            raise Refused("file/directory destination conflict")
    if not MANDATORY.issubset({p.upper() for p in canonical}):
        raise Refused("missing EFI, boot.wim or Windows Setup filename")
    installed=[kind for name,kind in INSTALL_KINDS.items()
               if name.casefold() in canonical]
    if len(installed)!=1:
        raise Refused("ambiguous/missing WIM or ESD installation payload")
    if any(p.upper().startswith("SOURCES/INSTALL") and p.upper().endswith(".SWM")
           for p in canonical):
        raise Refused("manifest already contains SWM namespace, requires separate audit")
    return canonical,total,installed[0]

def estimate_layout(doc,disk_gib,manifest_digest=None):
    if type(disk_gib) is not int or not MIN_GIB<=disk_gib<=MAX_GIB:
        raise Refused("virtual disk nominal capacity must be 1–24 GiB")
    files,read_bytes,install_kind=validate_manifest(doc)
    install_entry=files[f"sources/install.{install_kind.lower()}"]
    install_bytes=install_entry["bytes"]
    needs_split=install_kind=="WIM" and install_bytes>MAX_FAT32_FILE
    blockers=[]
    if install_kind=="ESD" and install_bytes>MAX_FAT32_FILE:
        blockers.append("oversized_esd_without_independently_qualified_conversion")
    if any(item["bytes"]>MAX_FAT32_FILE
           for path,item in files.items() if path!=f"sources/install.{install_kind.lower()}"):
        blockers.append("other_iso_file_exceeds_fat32_single_file_limit")
    efi_files=[]
    payload_files=[]
    for item in files.values():
        dest="efi" if item["path"].casefold().startswith("efi/") else "payload"
        rec={"path":item["path"],"bytes":item["bytes"],"sha256":item["sha256"],
             "proposedPartition":dest}
        (efi_files if dest=="efi" else payload_files).append(rec)
    efi_sum=sum(item["bytes"] for item in efi_files)
    payload_sum=sum(item["bytes"] for item in payload_files)
    proposed_swm_max_parts=None
    proposed_swm_budget=None
    if needs_split:
        # Split-WIM has metadata overhead and cannot be predicted exactly
        # from WIM bytes. This is a *budget*, not fabricated SWM part hashes.
        proposed_swm_max_parts=(install_bytes+SWM_TARGET-1)//SWM_TARGET
        if proposed_swm_max_parts>256:
            blockers.append("estimated_split_part_count_excessive")
        proposed_swm_budget=(install_bytes*105+99)//100 + 128*MIB
        payload_sum=payload_sum-install_bytes+proposed_swm_budget
        payload_files=[
            {**p,"stageAction":"replace_with_verified_swm",
             "replacementFilesPresent":False}
            if p["path"].casefold()=="sources/install.wim" else p
            for p in payload_files]
        blockers.append("verified_swm_split_and_genuine_large_payload_staging_not_qualified")
    available_efi=EFI_MIB*MIB-EFI_HEADROOM
    efi_budget=efi_sum+len(efi_files)*MIN_FILE_OVERHEAD
    if efi_budget>available_efi:
        blockers.append("efi_partition_capacity_exceeded")
    disk_bytes=disk_gib*GIB
    disk_lbas=disk_bytes//512
    esp_first_lba=GPT_ALIGNMENT//512
    esp_last_lba=esp_first_lba+(EFI_MIB*MIB)//512-1
    payload_first_lba=esp_last_lba+1
    payload_last_lba=disk_lbas-34
    payload_partition_bytes=(payload_last_lba-payload_first_lba+1)*512
    # Overestimate occupied clusters, FAT entries, directory overhead, and
    # leave 64 MiB free; exact fatfs allocator feasibility is still untested.
    payload_budget=(payload_sum*115+99)//100+len(payload_files)*MIN_FILE_OVERHEAD+PAYLOAD_HEADROOM
    if payload_budget>payload_partition_bytes:
        blockers.append("fat32_payload_partition_capacity_exceeded")
    if not blockers:
        blockers.append("complete_real_iso_to_virtual_disk_staging_unimplemented")
    # Always retain independent trust/boot blockers, even when sizing fits.
    blockers.extend([
        "fresh_publisher_iso_and_each_file_sha_reverification_required",
        "actual_uefi_secure_boot_tpm_windows_setup_unverified",
        "no_physical_usb_writer_authority",
    ])
    return {
        "schema":"bootnexa-windows-installer-layout-plan-v1",
        "virtualOnly":True,"readOnly":True,
        "physicalWriteAuthorized":False,"installerCompatibleVerified":False,
        "windowsSetupBootVerified":False,"fullDiskSha256Verified":False,
        "manifestAssertionsTrusted":False,
        "requiresLivePublisherAndSourceReverification":True,
        "actualSplitWimArtifactsVerified":False,
        "ntfsWriterAvailable":False,"splitWimFilesGenerated":False,
        "virtualDiskGenerated":False,"actionable":False,
        "inputManifestSha256":manifest_digest,
        "inputIsoSha256":doc["sourceSha256"],
        "inputFileCount":len(files),"inputFileBytes":read_bytes,
        "installationPayloadKind":install_kind,
        "installationPayloadBytes":install_bytes,
        "fat32MaxSingleFileBytes":MAX_FAT32_FILE,
        "requiresSplitWim":needs_split,
        "proposedWimlibSplitTargetBytes":SWM_TARGET if needs_split else None,
        "estimatedSplitPartsNotGuaranteed":proposed_swm_max_parts,
        "estimatedSplitPayloadBudgetBytes":proposed_swm_budget,
        "proposedDiskCapacityBytes":disk_bytes,
        "proposedPartitionLayout":{
            "protectiveMbrAndGptHeadersOnly":True,
            "proposedOnly":True,
            "efi":{"kind":"GPT EFI system partition, FAT32","bytes":EFI_MIB*MIB,
                   "firstLba":esp_first_lba,"lastLba":esp_last_lba,
                   "reservedHeadroomBytes":EFI_HEADROOM,"fileCount":len(efi_files),
                   "estimatedOccupancyBytes":efi_budget},
            "payload":{"kind":"GPT Microsoft basic data, FAT32 only, proposed",
                       "bytes":payload_partition_bytes,
                       "firstLba":payload_first_lba,"lastLba":payload_last_lba,"reservedHeadroomBytes":PAYLOAD_HEADROOM,
                       "fileCount":len(payload_files),"estimatedOccupancyBytes":payload_budget},
        },
        "filePlacements":efi_files+payload_files,
        "blockers":blockers,
        "state":"non_actionable_capacity_feasibility_only",
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--disk-gib",type=int,required=True)
    args=p.parse_args()
    try:
        doc,sha=read_manifest(args.manifest)
        plan=estimate_layout(doc,args.disk_gib,sha)
    except (Refused,ValueError,OSError,TypeError) as exc:
        print("DENIED: "+str(exc),file=sys.stderr)
        return 1
    print(json.dumps(plan,indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
