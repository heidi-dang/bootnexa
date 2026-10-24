#!/usr/bin/env python3
"""QEMU acceptance pipeline smoke: synthetic ISO *must not* claim Windows Setup.

This checks QEMU process isolation, Unix QMP/graphical screenshots, and
pinned source hashes. It contains no genuine Microsoft installation payload.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
GATE=ROOT/"tests/virtual-media/windows_setup_ovmf_gate.py"

with tempfile.TemporaryDirectory(prefix="bootnexa-win-evidence-ci-") as folder:
    root=Path(folder)
    image=root/"not-windows.iso"
    # Sparse, minimum-sized ISO recognition fixture. No real bootable OS.
    with image.open("wb") as stream:
        stream.truncate(512*1024*1024)
        stream.seek(16*2048)
        stream.write(b"\x01CD001\x01")
    with image.open("rb") as f:
        digest=hashlib.file_digest(f,"sha256").hexdigest()
    before=list(root.iterdir())
    mismatch=subprocess.run([
        sys.executable,str(GATE),"--iso",str(image),
        "--sha256","0"*64,"--evidence-parent",str(root),
        "--seconds","30",
    ],capture_output=True,text=True)
    assert mismatch.returncode!=0,mismatch.stdout
    assert list(root.iterdir())==before
    print("PASS synthetic ISO hash mismatch rejected without evidence dir")

    result=subprocess.run([
        sys.executable,str(GATE),"--iso",str(image),
        "--sha256",digest,"--evidence-parent",str(root),
        "--seconds","30",
    ],capture_output=True,text=True,timeout=55)
    assert result.returncode==0,(result.stderr,result.stdout)
    receipt=json.loads(result.stdout)
    evidence=Path(receipt["evidenceDirectory"])
    assert evidence.is_dir() and (evidence/"evidence.json").is_file()
    assert receipt["virtualOnly"] is True
    assert receipt["physicalWriteAuthorized"] is False
    assert receipt["operatorSha256Matched"] is True
    assert receipt["publisherProvenanceVerified"] is False
    assert receipt["windowsSetupBootVerified"] is False
    assert receipt["graphicalWindowsSetupObserved"] is False
    assert receipt["networkConnected"] is False
    assert receipt["hostDiskAttached"] is False
    assert receipt["bootAttempted"] is True
    assert receipt["isoUnchangedAfterVm"] is True
    if not receipt["graphicalCaptureSucceeded"]:
        log=evidence/"qemu.log"
        print("QEMU startup/capture diagnostic:",log.read_text(errors="replace")[-2000:] if log.exists() else "missing log",file=sys.stderr)
        print("QEMU termination facts:",{k:receipt.get(k) for k in
              ("qemuExitCode","qemuExitedEarly","qemuElapsedSeconds","failure")},file=sys.stderr)
    assert receipt["graphicalCaptureSucceeded"] is True
    assert len(receipt["screenshots"])>=1
    for captured in receipt["screenshots"]:
        frame=evidence/captured["name"]
        assert frame.read_bytes().startswith(b"P6")
        with frame.open("rb") as stream:
            assert hashlib.file_digest(stream,"sha256").hexdigest()==captured["sha256"]
    with image.open("rb") as stream:
        assert hashlib.file_digest(stream,"sha256").hexdigest()==digest
    print(f"PASS QEMU/OVMF read-only synthetic ISO, {len(receipt['screenshots'])} graphical QMP frame(s) and full SHA evidence")
    print("PASS no guest network, host disk, publisher assertion, Windows Setup assertion, or USB writes")
