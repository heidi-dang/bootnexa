#!/usr/bin/env python3
"""Verified bounded ISO9660/UDF byte-stream -> anonymous FAT32 GPT demo.

Production path obtains Microsoft's current reference. A synthetic fixture
may invoke stage_verified_stream() only from tests with an injected fake
reference. No persistent raw image, guest boot, or physical device writes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import sys
import time
import windows_iso_publisher_manifest as source_gate
import windows_installer_layout_plan as planner

MAX_FILE=32*1024*1024
MAX_TOTAL=128*1024*1024
MAX_FILES=128
BUF=65536
MAGIC=b"BNXI0001"
MAX_DURATION=900

class Refused(ValueError):
    pass

def validated_files(manifest):
    entries=manifest["files"]
    if not 4<=len(entries)<=MAX_FILES:
        raise Refused("ISO fixture has too many or too few files for bounded staging")
    total=0
    for item in entries:
        path=item["path"]
        planner.safe_fat_path(path)
        if not isinstance(path,str) or not 1<=len(path)<=240 or \
           not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",p) for p in path.split("/")):
            raise Refused("unsupported FAT32 path in stream demo")
        if any(p.startswith(("-", " ")) or p.endswith((".", " ")) for p in path.split("/")):
            raise Refused("ambiguous filename")
        n=item["bytes"]
        if type(n) is not int or n>MAX_FILE:
            raise Refused("individual ISO source exceeds 32 MiB demo limit")
        total+=n
        if total>MAX_TOTAL:
            raise Refused("ISO source exceeds 128 MiB demo aggregate limit")
        if not re.fullmatch(r"[a-f0-9]{64}",item["sha256"]):
            raise Refused("invalid file hash")
    names={item["path"].casefold() for item in entries}
    if names.__contains__("sources/install.wim")==names.__contains__("sources/install.esd"):
        raise Refused("requires exactly one install.wim or install.esd source")
    return entries,total

def stage_verified_stream(iso,reference,capacity,*,minimum=source_gate.MIN_OFFICIAL_ISO,
                          exe=None,agent=None):
    iso=source_gate.safe_regular(iso)
    if type(capacity) is not int or not 1<=capacity<=24:
        raise Refused("virtual capacity outside 1–24 GiB")
    exe=exe or source_gate.sevenzip_executable()
    agent=agent or Path("agent/target/debug/bootnexa-media").resolve()
    agent=source_gate.safe_regular(agent)
    # Entire ISO must match the independently acquired reference and all
    # file hashes must be read from the optical image BEFORE any staging.
    manifest=source_gate.build_manifest(iso,reference,minimum=minimum,
                                        require_windows=True,exe=exe)
    entries,total=validated_files(manifest)
    args=[str(agent),"stage-large-iso-stdin-demo",str(capacity)]
    begin=time.monotonic()
    disk=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    try:
        disk.stdin.write(MAGIC+struct.pack("<H",len(entries)))
        for entry in entries:
            if time.monotonic()-begin>MAX_DURATION:
                raise Refused("total ISO transfer time exceeded")
            raw=entry["path"].encode("ascii")
            expected=bytes.fromhex(entry["sha256"])
            disk.stdin.write(struct.pack("<H",len(raw))+raw+
                             struct.pack("<Q",entry["bytes"])+expected)
            extractor=subprocess.Popen([
                exe,"x","-so","-bd","-spd",str(iso),entry["path"]
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL)
            count=0
            sha=hashlib.sha256()
            try:
                while True:
                    remaining=MAX_DURATION-(time.monotonic()-begin)
                    if remaining<=0 or not select.select(
                        [extractor.stdout],[],[],min(30,remaining))[0]:
                        raise Refused("ISO extractor timeout")
                    data=os.read(extractor.stdout.fileno(),BUF)
                    if not data:
                        break
                    count+=len(data)
                    if count>entry["bytes"]:
                        raise Refused("ISO file grew beyond verified manifest")
                    sha.update(data)
                    disk.stdin.write(data)
                if extractor.wait(timeout=5)!=0 or count!=entry["bytes"] or \
                   sha.hexdigest()!=entry["sha256"]:
                    raise Refused("ISO extracted stream differs from verified source")
            finally:
                extractor.stdout.close()
                if extractor.poll() is None:
                    extractor.kill()
                    extractor.wait()
        disk.stdin.close()
        # Bounded Rust JSON report; no disk image is ever exposed or saved.
        # stdin was closed after the final file; read bounded response pipes.
        stdout=disk.stdout.read(1024*1024+1)
        stderr=disk.stderr.read(65537)
        if len(stdout)>1024*1024 or len(stderr)>65536:
            raise Refused("virtual disk agent report exceeded budget")
        if disk.wait(timeout=10)!=0:
            raise Refused("virtual disk agent rejected verified stream")
        report=json.loads(stdout)
    except (BrokenPipeError,OSError,subprocess.SubprocessError,ValueError) as exc:
        raise Refused("ISO-to-virtual staging failed closed") from exc
    finally:
        if disk.poll() is None:
            disk.kill()
            disk.wait()
        disk.stdout.close()
        disk.stderr.close()
        if not disk.stdin.closed:
            disk.stdin.close()
    if report.get("stagedFileCount")!=len(entries) or report.get("stagedBytes")!=total or \
       not all(report.get(k) is True for k in (
           "virtualOnly","gptIntegrityVerified","efiFat32Verified","payloadFat32Verified"
       )) or any(report.get(k) is not False for k in (
           "physicalWriteAuthorized","windowsSetupBootVerified",
           "installerCompatibleVerified","fullDiskSha256Verified"
       )):
        raise Refused("virtual FAT32 agent made unexpected assertions")
    recorded={item["path"].casefold():item for item in report["files"]}
    if len(recorded)!=len(entries):
        raise Refused("virtual FAT32 report contains duplicate names")
    for item in entries:
        actual=recorded.get(item["path"].casefold())
        if actual is None or actual["bytes"]!=item["bytes"] or \
           actual["sha256"]!=item["sha256"] or \
           actual["independentFat32ReadbackVerified"] is not True:
            raise Refused("virtual FAT32 file digest/length mismatch")
    # Entire source ISO rehashed again after staging.
    after_size,after_sha=source_gate.file_sha(iso,source_gate.MAX_ISO)
    if (after_size,after_sha)!=(manifest["sourceBytes"],manifest["sourceSha256"]):
        raise Refused("ISO source changed during virtual transfer")
    return {
        "schema":"bootnexa-iso-to-anonymous-fat32-v1",
        "virtualOnly":True,
        "physicalWriteAuthorized":False,
        "windowsSetupBootVerified":False,
        "installerCompatibleVerified":False,
        "fullDiskSha256Verified":False,
        "persistentDiskImageProduced":False,
        "actualWimResourcesVerified":False,
        "fullSizeWindowsInstallerSupported":False,
        "sourceIsoUnchangedVerified":True,
        "sourceIsoSha256":after_sha,
        "allIsoFilesIndependentlyHashedBeforeStaging":True,
        "stagedBytes":total,
        "stagedFileCount":len(entries),
        "virtualGptMetadataVerified":True,
        "fat32ReadbackFiles":report["files"],
        "publisherReferenceObtainedLiveForThisRun":(
            reference.get("issuer")=="Microsoft public download-page HTTPS response"),
        "publisherChecksumMatched":True,
        "sourceBytes":after_size,
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso",type=Path,required=True)
    parser.add_argument("--locale",choices=source_gate.SUPPORTED_LOCALES,required=True)
    parser.add_argument("--disk-gib",type=int,required=True)
    args=parser.parse_args()
    try:
        reference=source_gate.fetch_publisher_reference(args.locale)
        receipt=stage_verified_stream(args.iso,reference,args.disk_gib)
    except (Refused,source_gate.Rejected,OSError,ValueError) as exc:
        print("DENIED: "+str(exc),file=sys.stderr)
        return 1
    print(json.dumps(receipt,indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
