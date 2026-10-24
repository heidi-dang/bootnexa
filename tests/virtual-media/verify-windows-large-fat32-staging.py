#!/usr/bin/env python3
"""Synthetic-only, anonymous two-partition FAT32 and EFI qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

CLI=Path("agent/target/debug/bootnexa-media")
assert CLI.is_file(),"build native bootnexa-media before Python qualification"
def invoke(*args):
    return subprocess.run([str(CLI),*map(str,args)],capture_output=True,text=True,timeout=90)

with tempfile.TemporaryDirectory(prefix="bootnexa-fat32-stage-") as temp:
    root=Path(temp)
    source=root/"synthetic.bin"
    data=bytes(range(256))*8192
    source.write_bytes(data)
    digest=hashlib.sha256(data).hexdigest()
    for gib in (1,8):
        resp=invoke("stage-large-windows-payload-demo",gib,source,digest)
        assert resp.returncode==0,(gib,resp.stderr)
        receipt=json.loads(resp.stdout)
        assert receipt["virtualOnly"] is True
        assert receipt["physicalWriteAuthorized"] is False
        assert receipt["windowsSetupBootVerified"] is False
        assert receipt["installerCompatibleVerified"] is False
        assert receipt["fullDiskSha256Verified"] is False
        assert receipt["primaryAndBackupGptVerified"] is True
        assert receipt["payloadFat32Verified"] is True
        assert receipt["sourceSha256"]==digest
        assert receipt["fat32ReadbackSha256"]==digest
        assert receipt["sourceAfterSha256"]==digest
        assert receipt["sourceBytes"]==len(data)
        assert receipt["stagedPath"]=="SOURCES/PAYLOAD.BIN"
        assert hashlib.sha256(source.read_bytes()).hexdigest()==digest
        print(f"PASS {gib} GiB isolated FAT32 payload staging with 3-way SHA checks")

    standalone=invoke("qualify-large-windows-fat32",24)
    assert standalone.returncode==0,standalone.stderr
    report=json.loads(standalone.stdout)
    assert report["diskBytes"]==24*1024**3
    assert report["espFat32Verified"] and report["payloadFat32Verified"]
    assert report["payloadFilesystemFormatted"] and not report["ntfsWriterAvailable"]
    assert not report["windowsInstallerCompatible"] and not report["fullDiskSha256Verified"]
    assert not report["reservedPayloadSampledZero"]
    print("PASS 24 GiB sparse anonymous two-partition FAT32 filesystem integrity")

    wrong=invoke("stage-large-windows-payload-demo",1,source,"0"*64)
    assert wrong.returncode!=0 and not wrong.stdout.strip()
    fake=root/"fake-source"
    fake.symlink_to(source)
    assert invoke("stage-large-windows-payload-demo",1,fake,digest).returncode!=0
    oversize=root/"oversize.bin"
    with oversize.open("wb") as file:file.truncate(33*1024*1024)
    assert invoke("stage-large-windows-payload-demo",1,oversize,
                  hashlib.sha256(b"irrelevant").hexdigest()).returncode!=0
    print("PASS incorrect hash, symlink and source size refusal")

    pe=bytearray(512)
    pe[:2]=b"MZ"
    pe[0x3c:0x40]=(0x80).to_bytes(4,"little")
    pe[0x80:0x84]=b"PE\x00\x00"
    pe[0x84:0x86]=bytes([0x64,0x86])
    pe[0x98:0x9a]=bytes([0x0b,0x02])
    pe[0xdc:0xde]=(10).to_bytes(2,"little")
    efi=root/"BOOTX64.EFI";efi.write_bytes(pe)
    valid=invoke("stage-large-windows-efi-demo",1,efi)
    assert valid.returncode==0,valid.stderr
    e=json.loads(valid.stdout)
    assert e["efiStructureVerified"] and e["efiSourceUnchanged"]
    assert not e["efiExecutabilityVerified"]
    assert not e["physicalWriteAuthorized"] and not e["windowsSetupBootVerified"]
    assert e["efiSourceSha256"]==hashlib.sha256(pe).hexdigest()
    assert e["efiFat32ReadbackSha256"]==e["efiSourceSha256"]
    assert e["layout"]["reservedPayloadSampledZero"] is True
    assert e["layout"]["payloadFilesystemFormatted"] is False
    efi.write_bytes(b"NOT-PE"+bytes(506))
    assert invoke("stage-large-windows-efi-demo",1,efi).returncode!=0
    print("PASS bounded UEFI structural demo stays isolated from unformatted reserved partition")

print("PASS large sparse FAT32 staging; no physical writes, Windows Setup or persistent output")
