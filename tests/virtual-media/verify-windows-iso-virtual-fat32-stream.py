#!/usr/bin/env python3
"""No proprietary media: stream all synthetic ISO files to anonymous GPT/FAT32."""
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

mod=Path(__file__).with_name("windows_iso_virtual_fat32_stream.py")
spec=importlib.util.spec_from_file_location("iso_fat32_stream",mod)
stream=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stream)
agent=Path("agent/target/debug/bootnexa-media").resolve()
assert agent.is_file(),"build bootnexa-media first"

with tempfile.TemporaryDirectory(prefix="bootnexa-streamed-iso-") as td:
    base=Path(td)
    efi=base/"TESTX64.EFI"
    data=bytearray(512)
    data[:2]=b"MZ"
    data[0x3c:0x40]=(0x80).to_bytes(4,"little")
    data[0x80:0x84]=b"PE\x00\x00"
    data[0x84:0x86]=bytes([0x64,0x86])
    data[0x98:0x9a]=bytes([0x0b,0x02])
    data[0xdc:0xde]=(10).to_bytes(2,"little")
    efi.write_bytes(data)
    iso=base/"fixture.iso"
    subprocess.run([sys.executable,"tests/virtual-media/create-iso-fixture.py",
                    str(efi),str(iso),"--profile","windows-preflight"],check=True)
    iso_digest=hashlib.sha256(iso.read_bytes()).hexdigest()
    fake_ref={"referenceSha256":iso_digest,"issuer":"untrusted synthetic fixture","locale":"unit test"}
    old={p.name for p in base.iterdir()}
    for gib in (1,8):
        result=stream.stage_verified_stream(
            iso,fake_ref,gib,minimum=1,
            exe=shutil.which("7z"),agent=agent)
        assert result["stagedFileCount"]>=5
        assert result["stagedBytes"]>0
        assert result["virtualGptMetadataVerified"]
        assert result["sourceIsoUnchangedVerified"]
        assert result["sourceIsoSha256"]==iso_digest
        assert not result["publisherReferenceObtainedLiveForThisRun"]
        assert not result["windowsSetupBootVerified"]
        assert not result["fullSizeWindowsInstallerSupported"]
        assert not result["physicalWriteAuthorized"]
        assert not result["persistentDiskImageProduced"]
        names={x["path"] for x in result["fat32ReadbackFiles"]}
        assert {"EFI/BOOT/BOOTX64.EFI","SOURCES/BOOT.WIM",
                "SOURCES/INSTALL.WIM","SETUP.EXE"}.issubset(names),names
        assert all(x["independentFat32ReadbackVerified"] for x in result["fat32ReadbackFiles"])
        print(f"PASS {gib} GiB anonymous dual FAT32: {len(names)} source files streamed directly from ISO and SHA-verified by Rust")
    assert {p.name for p in base.iterdir()}==old
    print("PASS no host file extraction and no persistent output image")

    def frame(path,content,override=None):
        encoded=path.encode()
        return (stream.MAGIC+struct.pack("<H",4)
                +struct.pack("<H",len(encoded))+encoded
                +struct.pack("<Q",len(content))
                +(bytes.fromhex(override) if override else hashlib.sha256(content).digest())
                +content)
    cases=[
        ("bad-header",b"wrong header"),
        ("traversal",frame("../TRAVERSAL",b"xyz")),
        ("reserved-dos-name",frame("COM9.TXT",b"xyz")),
        ("wrong-hash",frame("SETUP.EXE",b"xyz","0"*64)),
        ("truncated",stream.MAGIC+struct.pack("<H",4)+b"\x05"),
        ("bad-capacity",stream.MAGIC+struct.pack("<H",4)),
    ]
    for name,blob in cases:
        gib=0 if name=="bad-capacity" else 1
        denied=subprocess.run([str(agent),"stage-large-iso-stdin-demo",str(gib)],
                              input=blob,capture_output=True,timeout=35)
        assert denied.returncode!=0 and not denied.stdout.strip(),(name,denied.stdout)
        print(f"PASS malformed framed input refused: {name}")
    fake_bad=dict(fake_ref,referenceSha256="0"*64)
    try:
        stream.stage_verified_stream(iso,fake_bad,1,minimum=1,
                                     exe=shutil.which("7z"),agent=agent)
    except stream.source_gate.Rejected:
        print("PASS source ISO/reference mismatch refused before Rust disk creation")
    else:
        raise AssertionError("reference mismatch should be refused")
    try:
        stream.stage_verified_stream(iso,fake_ref,0,minimum=1,
                                     exe=shutil.which("7z"),agent=agent)
    except stream.Refused:
        print("PASS virtual disk capacity out of bounds refused")
    else:
        raise AssertionError("zero virtual capacity should be refused")
print("PASS synthetic-only ISO→anonymous GPT/FAT32 pipeline; Windows Setup remains unverified")
