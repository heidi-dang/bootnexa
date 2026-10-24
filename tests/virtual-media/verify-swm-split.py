#!/usr/bin/env python3
"""Exercise real open-source wimlib verification/splitting with synthetic files.

Runs without Microsoft's Windows images. Outputs are regular files only.
"""
from pathlib import Path
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile

cli=Path(sys.argv[1] if len(sys.argv)>1 else "agent/target/debug/bootnexa-media").resolve()
wimlib="wimlib-imagex"

def run(*args):
    return subprocess.run([str(x) for x in args],capture_output=True,text=True)

def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source,"sha256").hexdigest()

with tempfile.TemporaryDirectory(prefix="bootnexa-swm-fixture-") as tmp:
    root=Path(tmp)
    raw=root/"synthetic-files"
    raw.mkdir()
    prng=random.Random(0xB007)
    for i in range(14):
        (raw/f"fixture-{i:02d}.bin").write_bytes(prng.randbytes(320*1024))
    source=root/"synthetic.wim"
    capture=run(wimlib,"capture",raw,source,"BootNexa synthetic test image","--compress=LZX")
    assert capture.returncode==0,capture.stderr
    verified=run(wimlib,"verify",source)
    assert verified.returncode==0,verified.stderr
    before=digest(source)
    result=run(cli,"split-wim-virtual",source,root,"1")
    assert result.returncode==0,(result.stderr,result.stdout)
    receipt=json.loads(result.stdout)
    assert receipt["virtualOnly"] is True
    assert receipt["physicalWriteAuthorized"] is False
    assert receipt["installerCompatibleVerified"] is False
    assert receipt["windowsSetupBootVerified"] is False
    assert receipt["splitWimIntegrityVerified"] is True
    assert receipt["allPartsFitFat32"] is True
    assert receipt["sourceSha256"]==before==digest(source)
    parts=receipt["parts"]
    assert len(parts)>=2,parts
    directory=Path(receipt["outputDirectory"])
    assert directory.parent==root and directory.is_dir()
    for i,part in enumerate(parts):
        expected="install.swm" if i==0 else f"install{i+1}.swm"
        assert part["filename"]==expected
        swm=directory/expected
        assert swm.is_file() and not swm.is_symlink()
        assert swm.stat().st_size==part["bytes"]
        assert part["sha256"]==digest(swm)
        assert 0<part["bytes"]<=0xffffffff
    assert run(wimlib,"verify",directory/"install.swm",
               f"--ref={directory}/install*.swm").returncode==0
    print(f"PASS real wimlib captured, split, verified {len(parts)} SWM files from synthetic WIM")
    print("PASS source-before-after, per-part readback SHA-256 and FAT32 limits")

    # Populate a bounded synthetic GPT/FAT32 virtual disk from a qualified
    # split-WIM set and fixed Windows-shaped paths. Not genuine Setup media.
    stage=root/"staging"
    (stage/"EFI/BOOT").mkdir(parents=True)
    (stage/"SOURCES").mkdir()
    (stage/"SOURCES/BOOT.WIM").write_bytes(source.read_bytes())
    pe=bytearray(512)
    pe[:2]=b"MZ"
    pe[0x3c:0x40]=(0x80).to_bytes(4,"little")
    pe[0x80:0x84]=b"PE\x00\x00"
    pe[0x84:0x86]=bytes([0x64,0x86])
    pe[0x98:0x9a]=bytes([0x0b,0x02])
    pe[0xdc:0xde]=(10).to_bytes(2,"little")
    (stage/"EFI/BOOT/BOOTX64.EFI").write_bytes(pe)
    (stage/"SETUP.EXE").write_bytes(b"MZ"+bytes(510))
    before_stage={p.relative_to(stage).as_posix():digest(p)
                  for p in stage.rglob("*") if p.is_file()}
    demos=lambda:set(root.glob("bootnexa-windows-swm-demo-*.img"))
    assembled=run(cli,"build-windows-swm-demo",stage,directory,root)
    assert assembled.returncode==0,(assembled.stderr,assembled.stdout)
    image=json.loads(assembled.stdout)
    disk=Path(image["outputPath"])
    assert disk.parent==root
    assert disk.stat().st_size==192*1024*1024
    assert digest(disk)==image["outputSha256"]
    assert image["virtualOnly"] and not image["physicalWriteAuthorized"]
    assert not image["installerCompatibleVerified"]
    assert not image["windowsSetupBootVerified"]
    assert image["media"]["verifiedFiles"]==len(parts)+3
    assert image["media"]["verifiedBytes"]==sum(p.stat().st_size
        for p in stage.rglob("*") if p.is_file())+sum(p["bytes"] for p in parts)
    assert before_stage=={p.relative_to(stage).as_posix():digest(p)
                          for p in stage.rglob("*") if p.is_file()}
    for part in parts:
        assert part["sha256"]==digest(directory/part["filename"])
    print("PASS real verified multi-part SWM with EFI/BOOT/BOOTX64.EFI, BOOT.WIM and SETUP.EXE -> 192MiB GPT/FAT32 disk + independent SHA readback")

    previous=demos()
    original=(stage/"EFI/BOOT/BOOTX64.EFI").read_bytes()
    (stage/"EFI/BOOT/BOOTX64.EFI").write_bytes(b"NOT-EFI")
    assert run(cli,"build-windows-swm-demo",stage,directory,root).returncode!=0
    assert demos()==previous
    (stage/"EFI/BOOT/BOOTX64.EFI").write_bytes(original)
    print("PASS malformed EFI header rejects virtual disk and creates no output")

    original=(directory/"install2.swm").read_bytes()
    (directory/"install2.swm").write_bytes(original[:64]+b"EVIL"+original[68:])
    assert run(cli,"build-windows-swm-demo",stage,directory,root).returncode!=0
    assert demos()==previous
    (directory/"install2.swm").write_bytes(original)
    print("PASS corrupted SWM part rejects virtual disk without creating output")

    bad_stage=root/"staging-symlink"
    bad_stage.symlink_to(stage,target_is_directory=True)
    assert run(cli,"build-windows-swm-demo",bad_stage,directory,root).returncode!=0
    print("PASS rejects symlinked Windows source root")

    anchor=root/"existing-marker.txt"
    anchor.write_text("unmodified")
    bad=root/"invalid.wim"
    bad.write_bytes(b"MSWIM-not-valid")
    count=lambda:len(list(root.glob("bootnexa-swm-*")))
    prior=count()
    for name,argv in [
        ("invalid-wim",[bad,root,"1"]),
        ("zero-size",[source,root,"0"]),
        ("over-3800",[source,root,"3801"]),
    ]:
        call=run(cli,"split-wim-virtual",*argv)
        assert call.returncode!=0,(name,call.stdout)
        assert count()==prior,name
        print(f"PASS denies {name} without leaving partial output")
    symlink=root/"redirected-output"
    symlink.symlink_to(root,target_is_directory=True)
    assert run(cli,"split-wim-virtual",source,symlink,"1").returncode!=0
    symlink_source=root/"linked.wim"
    symlink_source.symlink_to(source)
    assert run(cli,"split-wim-virtual",symlink_source,root,"1").returncode!=0
    assert anchor.read_text()=="unmodified"
    print("PASS rejects symlink input/output and preserves pre-existing files")
print("PASS signed-off synthetic WIM/SWM-only CI contract (no Setup-boot claims)")
