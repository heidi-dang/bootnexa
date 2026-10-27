#!/usr/bin/env python3
"""Actual ISO9660 -> verified WIM split -> dual-FAT32 regression, synthetic only.

This test injects a synthetic reference into the INTERNAL Python function;
the production CLI has no reference injection flag and always fetches
Microsoft's pinned current HTTPS checksum independently.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

import windows_source_bound_combined_iso as pipeline

ROOT=Path.cwd()
AGENT=(ROOT/"agent/target/debug/bootnexa-media").resolve()
assert AGENT.is_file()
assert shutil.which("wimlib-imagex")
assert shutil.which("7z")
assert shutil.which("xorriso")


def command(*args):
    process=subprocess.run([str(a) for a in args],capture_output=True,
                           text=True,timeout=180)
    assert process.returncode==0,(args,process.stdout[-1500:],process.stderr[-1500:])


with tempfile.TemporaryDirectory(prefix="bootnexa-boundiso-test-",dir=ROOT) as td:
    root=Path(td)
    tree=root/"source-tree"
    (tree/"EFI/BOOT").mkdir(parents=True)
    (tree/"EFI/MICROSOFT/BOOT").mkdir(parents=True)
    (tree/"SOURCES").mkdir()
    (tree/"BOOT").mkdir()
    random_sources=root/"random-wim-files"
    random_sources.mkdir()
    for idx in range(4):
        with (random_sources/f"nonmicrosoft-{idx}.bin").open("wb") as out:
            for _ in range(4):
                out.write(os.urandom(1024*1024))
    command("wimlib-imagex","capture",random_sources,tree/"SOURCES/INSTALL.WIM",
            "BootNexa fake Windows installer","--compress=none")
    command("wimlib-imagex","verify",tree/"SOURCES/INSTALL.WIM")
    boot_src=root/"small-boot-source"
    boot_src.mkdir()
    (boot_src/"readme.txt").write_text("not Microsoft WinPE")
    command("wimlib-imagex","capture",boot_src,tree/"SOURCES/BOOT.WIM",
            "synthetic BOOT.WIM","--compress=none")
    command("wimlib-imagex","verify",tree/"SOURCES/BOOT.WIM")
    pe=bytearray(512)
    pe[:2]=b"MZ"
    pe[0x3c:0x40]=(0x80).to_bytes(4,"little")
    pe[0x80:0x84]=b"PE\x00\x00"
    pe[0x84:0x86]=b"\x64\x86"
    pe[0x98:0x9a]=b"\x0b\x02"
    (tree/"EFI/BOOT/BOOTX64.EFI").write_bytes(pe)
    (tree/"EFI/MICROSOFT/BOOT/BCD").write_bytes(b"non-Microsoft synthetic BCD")
    (tree/"SETUP.EXE").write_bytes(pe)
    (tree/"BOOT/BOOT.SDI").write_bytes(b"non-Microsoft synthetic boot.sdi")
    (tree/"README.TXT").write_bytes(b"not a Windows installer")
    iso=root/"synthetic-setup-layout.iso"
    command("xorriso","-as","mkisofs","-iso-level","3","-J","-R",
            "-V","BOOTNEXA_TEST_ONLY","-o",iso,tree)
    with iso.open("rb") as stream:
        expected=hashlib.file_digest(stream,"sha256").hexdigest()
    ref={"referenceSha256":expected,"issuer":"synthetic-only test reference",
         "locale":"non-Microsoft, test injection only"}
    source_before={p.relative_to(tree).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in tree.rglob("*") if p.is_file()}
    receipt=pipeline.stage_verified_combined(iso,ref,8,root,minimum=1,
        exe=shutil.which("7z"),agent=AGENT,part_mib=4,reference_live=False)
    assert receipt["isoSourceSha256"]==expected
    assert receipt["verifiedSwmPartCount"]>=2
    assert receipt["allFat32FileReadbacksVerified"] is True
    assert receipt["verifiedNonInstallFileCount"]>=6
    assert receipt["gptAndBothFat32PartitionsVerified"] is True
    assert receipt["sourceIsoUnchangedAfterTransfer"] is True
    assert receipt["publisherReferenceObtainedLiveForThisRun"] is False
    assert receipt["publisherChecksumMatched"] is False
    for key in ("physicalWriteAuthorized","persistentDiskImageProduced",
                "windowsSetupBootVerified","installerCompatibleVerified",
                "genuineWindowsSetupObserved","guestBootEvidenceCollected",
                "fullDiskSha256Verified"):
        assert receipt[key] is False,key
    assert not list(root.rglob("*.img"))
    assert {p.relative_to(tree).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in tree.rglob("*") if p.is_file()}==source_before
    assert not list(root.glob("bootnexa-sourcebound-iso-*"))
    print("PASS synthetic real ISO -> verified source WIM -> actual SWMs -> same anonymous 8GiB GPT/FAT32")
    print(f"PASS SHA-bound source ISO, {receipt['verifiedSwmPartCount']} SWM parts, {receipt['verifiedNonInstallFileCount']} other files, every FAT32 file rehashed")
    print("PASS no Microsoft provenance, no Setup boot claim, no disk output, scratch cleaned")

    bad=dict(ref,referenceSha256="0"*64)
    try:
        pipeline.stage_verified_combined(iso,bad,8,root,minimum=1,
            exe=shutil.which("7z"),agent=AGENT,part_mib=4)
    except pipeline.source_gate.Rejected:
        pass
    else:
        raise AssertionError("wrong ISO checksum was not denied")
    assert not list(root.glob("bootnexa-sourcebound-iso-*"))
    print("PASS wrong independent ISO checksum refuses before any scratch staging")
