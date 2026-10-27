#!/usr/bin/env python3
"""Operator-only, source-bound ISO->wimlib SWM->anonymous GPT/FAT32 qualification.

Production CLI fetches the exact Microsoft.com SHA itself; neither a stored
manifest nor an operator-provided checksum authorizes execution. Tests may
inject non-Microsoft references directly into stage_verified_combined.
A successful disk copy is NOT Windows Setup boot or publisher code signing.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time

import windows_iso_publisher_manifest as source_gate
import windows_installer_layout_plan as layout
import windows_iso_virtual_fat32_stream as ipc

GIB=1024**3
MIB=1024**2
MAX_INSTALL=16*GIB
MAX_REMAINDER=2*GIB
MAX_FILE=GIB
MAX_FILES=4096
MAX_DURATION=7200
BUF=65536
MAGIC=b"BNXI0002"


class Refused(ValueError):
    pass


def validated_remainder(manifest, capacity):
    if type(capacity) is not int or not 8<=capacity<=24:
        raise Refused("combined virtual disk requires nominal 8-24 GiB")
    records=manifest.get("files")
    if not isinstance(records,list) or not 5<=len(records)<=MAX_FILES:
        raise Refused("ISO file count outside combined virtual profile bounds")
    canonical=set()
    paths=set()
    remainder=[]
    install=None
    total=0
    for rec in records:
        if not isinstance(rec,dict) or set(rec)!={"path","bytes","sha256"}:
            raise Refused("invalid ISO file record")
        try:
            path=layout.safe_fat_path(rec["path"])
            path.encode("ascii")
        except (layout.Refused,UnicodeError,TypeError) as exc:
            raise Refused("ISO path cannot be represented safely on FAT32") from exc
        # EXACTLY the same 16-component ASCII namespace that Rust accepts.
        pieces=path.split("/")
        if not 1<=len(pieces)<=16 or not 1<=len(path.encode())<=240:
            raise Refused("ISO destination path too long")
        if any(not re.fullmatch("[A-Za-z0-9_.-]{1,100}",x) or
               x.startswith(("-", " ")) or x.endswith((".", " ")) for x in pieces):
            raise Refused("ISO destination contains unsupported FAT32 component")
        folded=path.casefold()
        if folded in canonical:
            raise Refused("case-folded destination collision")
        canonical.add(folded)
        paths.add(folded)
        size=rec["bytes"]
        if type(size) is not int or not 0<=size<=MAX_INSTALL:
            raise Refused("invalid ISO file byte length")
        digest=rec["sha256"]
        if not isinstance(digest,str) or not re.fullmatch("[a-f0-9]{64}",digest):
            raise Refused("invalid independently hashed ISO file SHA-256")
        if folded=="sources/install.wim":
            if install is not None or size==0:
                raise Refused("ambiguous/empty source WIM")
            install=rec
        elif folded=="sources/install.esd" or (
            folded.startswith("sources/install") and folded.endswith(".swm")):
            raise Refused("ESD or pre-existing SWM cannot enter combined WIM profile")
        else:
            if size>MAX_FILE:
                raise Refused("non-install file exceeds 1 GiB")
            total+=size
            if total>MAX_REMAINDER:
                raise Refused("non-install data exceeds 2 GiB budget")
            remainder.append(rec)
    for folded in canonical:
        parts=folded.split("/")
        if any("/".join(parts[:n]) in canonical for n in range(1,len(parts))):
            raise Refused("file/directory collision")
    if install is None:
        raise Refused("no verified install.wim in ISO")
    if not {"efi/boot/bootx64.efi","sources/boot.wim","setup.exe"}<=paths:
        raise Refused("required Windows-shaped paths absent")
    if len(remainder)<4:
        raise Refused("insufficient ISO remainder file count")
    return install,remainder,total


def space_admission(parent,install_bytes,remainder_bytes,capacity):
    if type(install_bytes) is not int or not 0<install_bytes<=MAX_INSTALL:
        raise Refused("invalid source WIM capacity")
    if type(remainder_bytes) is not int or not 0<=remainder_bytes<=MAX_REMAINDER:
        raise Refused("invalid remainder capacity")
    parent=source_gate.safe_parent(parent)
    free=os.statvfs(parent)
    available=free.f_bavail*free.f_frsize
    # Holds extracted source WIM, SWM archive, anonymous FAT32 staging,
    # directory metadata and a conservative extra 2 GiB host reserve.
    needed=3*install_bytes+2*remainder_bytes+2*GIB
    if available<needed:
        raise Refused("scratch host space insufficient for source-bound split and staging")
    if (install_bytes+remainder_bytes)*5//4+192*MIB > (
        capacity*GIB-257*MIB):
        raise Refused("conservative FAT32 payload occupancy exceeds nominal disk")
    return {"availableHostBytesAtPreflight":available,
            "requiredScratchBytesAtPreflight":needed}


def bounded_json_command(argv,env,deadline):
    remaining=min(1800,deadline-time.monotonic())
    if remaining<=0:
        raise Refused("native process deadline expired")
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,env=env,start_new_session=True)
    try:
        stdout,stderr=child.communicate(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        os.killpg(child.pid,signal.SIGKILL)
        child.communicate()
        raise Refused("native process exceeded 30 minute budget") from exc
    if child.returncode!=0 or len(stdout)>2*MIB or len(stderr)>65536:
        raise Refused("native wimlib split/verification refused source")
    try:
        return json.loads(stdout)
    except (ValueError,UnicodeError) as exc:
        raise Refused("invalid native qualification JSON") from exc


def stream_iso_entry(exe,iso,record,deadline,on_bytes):
    """Exact independently hashed 7z extraction with a deadline and bounded RAM."""
    child=subprocess.Popen([exe,"x","-so","-bd","-spd",str(iso),record["path"]],
                           stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,start_new_session=True)
    count=0
    sha=hashlib.sha256()
    try:
        while True:
            remaining=min(1800,deadline-time.monotonic())
            if remaining<=0 or not select.select([child.stdout],[],[],min(10,remaining))[0]:
                raise Refused("ISO decoder exceeded read deadline")
            block=os.read(child.stdout.fileno(),BUF)
            if not block:
                break
            count+=len(block)
            if count>record["bytes"]:
                raise Refused("ISO entry grew beyond manifest")
            sha.update(block)
            on_bytes(block)
        if child.wait(timeout=min(5,max(0.1,deadline-time.monotonic())))!=0:
            raise Refused("ISO decoder rejected entry")
        if count!=record["bytes"] or sha.hexdigest()!=record["sha256"]:
            raise Refused("live extracted ISO bytes differ from source manifest")
    finally:
        child.stdout.close()
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL)
            child.wait()


def stage_verified_combined(iso,reference,capacity,scratch_parent, *,
                            minimum=source_gate.MIN_OFFICIAL_ISO,
                            exe=None,agent=None,part_mib=3800,
                            reference_live=False):
    if type(part_mib) is not int or not 1<=part_mib<=3800:
        raise Refused("wimlib split budget must be 1..3800 MiB")
    iso=source_gate.safe_regular(iso)
    if not isinstance(reference,dict) or not re.fullmatch(
        "[a-f0-9]{64}",reference.get("referenceSha256","")):
        raise Refused("independently supplied reference missing digest")
    exe=exe or source_gate.sevenzip_executable()
    agent=source_gate.safe_regular(
        agent or Path("agent/target/release/bootnexa-media").resolve())
    # The entire file tree is reconstructed from a live scan of the ISO
    # immediately before staging, never from a previous JSON file.
    manifest=source_gate.build_manifest(iso,reference,minimum=minimum,
                                        require_windows=True,exe=exe)
    install,other,total=validated_remainder(manifest,capacity)
    free=space_admission(scratch_parent,install["bytes"],total,capacity)
    deadline=time.monotonic()+MAX_DURATION
    parent=source_gate.safe_parent(scratch_parent)
    with tempfile.TemporaryDirectory(prefix="bootnexa-sourcebound-iso-",dir=parent) as td:
        root=Path(td)
        env=os.environ.copy()
        env["TMPDIR"]=str(root)
        source_wim=root/"install.wim"
        with source_wim.open("xb") as dst:
            stream_iso_entry(exe,iso,install,deadline,dst.write)
        if source_gate.file_sha(source_wim,MAX_INSTALL)!=(install["bytes"],install["sha256"]):
            raise Refused("independently hashed temporary WIM differs from the ISO")
        split=bounded_json_command([str(agent),"split-wim-virtual",str(source_wim),
                                    str(root),str(part_mib)],env,deadline)
        if split.get("splitWimIntegrityVerified") is not True or (
            split.get("sourceSha256")!=install["sha256"]) or (
            split.get("sourceBytes")!=install["bytes"]) or (
            split.get("physicalWriteAuthorized") is not False):
            raise Refused("wimlib split not bound to original ISO WIM")
        split_dir=Path(split["outputDirectory"])
        if split_dir.parent!=root or split_dir.is_symlink() or not split_dir.is_dir():
            raise Refused("native split destination escaped dedicated scratch directory")
        parts=split["parts"]
        if not isinstance(parts,list) or not 2<=len(parts)<=64:
            raise Refused("invalid split part count")
        for index,part in enumerate(parts,1):
            expected="install.swm" if index==1 else f"install{index}.swm"
            src=split_dir/expected
            if part.get("filename")!=expected or src.is_symlink() or not src.is_file() or (
                src.stat().st_size!=part.get("bytes")) or not re.fullmatch(
                    "[a-f0-9]{64}",part.get("sha256","")):
                raise Refused("SWM part inconsistent with source WIM split receipt")
        if sum(p["bytes"] for p in parts)>16*GIB:
            raise Refused("actual SWM archive exceeds 16 GiB")
        child=subprocess.Popen([str(agent),"stage-combined-windows-tree-virtual",
                                str(capacity),str(split_dir),
                                "--experimental-virtual-only"],stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                env=env,start_new_session=True)
        try:
            os.set_blocking(child.stdin.fileno(),False)
            ipc._send_to_disk(child,MAGIC+struct.pack("<H",len(other)),deadline)
            for rec in other:
                name=rec["path"].encode("ascii")
                header=(struct.pack("<H",len(name))+name+
                        struct.pack("<Q",rec["bytes"])+bytes.fromhex(rec["sha256"]))
                ipc._send_to_disk(child,header,deadline)
                stream_iso_entry(exe,iso,rec,deadline,
                                 lambda block:ipc._send_to_disk(child,block,deadline))
            child.stdin.close()
            combined=ipc._collect_disk_report(child,deadline)
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            raise Refused("source-bound combined virtual stage failed closed") from exc
        finally:
            if child.poll() is None:
                os.killpg(child.pid,signal.SIGKILL)
                child.wait()
            child.stdout.close()
            child.stderr.close()
            if not child.stdin.closed:
                child.stdin.close()
        copied=combined.get("isoFiles",{})
        swm=combined.get("swm",{})
        actual=copied.get("files",[])
        index={x["path"].casefold():x for x in actual}
        if (combined.get("virtualCombinedLayoutVerified") is not True
            or combined.get("completeSourceIsoVerified") is not False
            or combined.get("physicalWriteAuthorized") is not False
            or combined.get("windowsSetupBootVerified") is not False
            or combined.get("installerCompatibleVerified") is not False
            or combined.get("persistentDiskImageProduced") is not False
            or not all(combined.get(key) is True for key in
                       ("efiFat32Verified","payloadFat32Verified","gptIntegrityVerified"))
            or copied.get("stagedBytes")!=total or copied.get("stagedFileCount")!=len(other)
            or len(index)!=len(other)
            or swm.get("stagedParts")!=parts
            or swm.get("hostStorageAdmissionPassed") is not True):
            raise Refused("native combined receipt lacks source-bound readback proof")
        for record in other:
            got=index.get(record["path"].casefold())
            if not got or (got["bytes"],got["sha256"])!=(
                record["bytes"],record["sha256"]) or (
                    got.get("independentFat32ReadbackVerified") is not True):
                raise Refused("FAT32 ISO remainder source digest mismatch")
        if source_gate.file_sha(source_wim,MAX_INSTALL)!=(
            install["bytes"],install["sha256"]):
            raise Refused("temporary install WIM mutated during combined stage")
        for part in parts:
            if source_gate.file_sha(split_dir/part["filename"],4*GIB)!=(
                part["bytes"],part["sha256"]):
                raise Refused("SWM source mutated during ISO staging")
        end_bytes,end_sha=source_gate.file_sha(iso,source_gate.MAX_ISO)
        if (end_bytes,end_sha)!=(
            manifest["sourceBytes"],manifest["sourceSha256"]):
            raise Refused("original ISO mutated during complete combined transfer")
        # Return no scratch or proprietary paths. These bytes have been erased
        # by the TemporaryDirectory exit when this function returns.
        return {
            "schema":"bootnexa-sourcebound-combined-virtual-v1",
            "isoSourceSha256":end_sha,
            "isoSourceBytes":end_bytes,
            "sourceIsoUnchangedAfterTransfer":True,
            "publisherReferenceObtainedLiveForThisRun":bool(reference_live),
            "publisherChecksumMatched":bool(reference_live),
            "independentReferenceDigestMatched":True,
            "allIsoFilesIndependentlyHashedBeforeStaging":True,
            "installWimSha256":install["sha256"],
            "installWimBytes":install["bytes"],
            "verifiedSwmPartCount":len(parts),
            "verifiedSwmBytes":sum(p["bytes"] for p in parts),
            "verifiedNonInstallFileCount":len(other),
            "verifiedNonInstallBytes":total,
            "allFat32FileReadbacksVerified":True,
            "gptAndBothFat32PartitionsVerified":True,
            "diskGiB":capacity,
            **free,
            "virtualOnly":True,
            "persistentDiskImageProduced":False,
            "physicalWriteAuthorized":False,
            "windowsSetupBootVerified":False,
            "installerCompatibleVerified":False,
            "fullDiskSha256Verified":False,
            "genuineWindowsSetupObserved":False,
            "guestBootEvidenceCollected":False,
            "manualWindowsSetupReviewRequired":True,
        }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso",type=Path,required=True)
    parser.add_argument("--locale",choices=source_gate.SUPPORTED_LOCALES,required=True)
    parser.add_argument("--scratch-parent",type=Path,required=True)
    parser.add_argument("--disk-gib",type=int,default=16)
    parser.add_argument("--part-mib",type=int,default=3800)
    parser.add_argument("--confirm-anonymous-virtual-only",action="store_true")
    parser.add_argument("--capture-iso-ovmf-evidence",action="store_true")
    parser.add_argument("--evidence-parent",type=Path)
    parser.add_argument("--ovmf-seconds",type=int,default=180)
    args=parser.parse_args()
    if not args.confirm_anonymous_virtual_only:
        parser.error("--confirm-anonymous-virtual-only is mandatory")
    if args.capture_iso_ovmf_evidence and args.evidence_parent is None:
        parser.error("--capture-iso-ovmf-evidence requires --evidence-parent")
    if not 30<=args.ovmf_seconds<=600:
        parser.error("--ovmf-seconds must be between 30 and 600")
    try:
        ref=source_gate.fetch_publisher_reference(args.locale)
        report=stage_verified_combined(
            args.iso,ref,args.disk_gib,args.scratch_parent,
            part_mib=args.part_mib,reference_live=True)
        if args.capture_iso_ovmf_evidence:
            # Separate source-ISO boot witness, NOT a proof the new anonymous
            # combined disk itself boots. QMP screenshots require review.
            import windows_setup_ovmf_gate as ovmf
            evidence=ovmf.run_gate(args.iso,ref["referenceSha256"],
                args.evidence_parent,args.ovmf_seconds,publisher_reference=ref)
            if (evidence.get("graphicalCaptureSucceeded") is not True or
                evidence.get("isoUnchangedAfterVm") is not True):
                raise Refused("guest QMP capture or ISO source re-verification failed")
            report["guestBootEvidenceCollected"]=True
            report["sourceIsoGuestEvidenceDirectory"]=evidence["evidenceDirectory"]
            report["sourceIsoGuestScreenshots"]=len(evidence["screenshots"])
            report["genuineWindowsSetupObserved"]=False
            report["windowsSetupBootVerified"]=False
            report["manualWindowsSetupReviewRequired"]=True
    except (Refused,source_gate.Rejected,layout.Refused,OSError,
            ValueError,subprocess.SubprocessError) as exc:
        print("DENIED: "+str(exc),file=sys.stderr)
        return 1
    print(json.dumps(report,indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
