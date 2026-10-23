#!/usr/bin/env python3
"""Adversarial, synthetic-only Windows-like ISO preflight and CD-ROM staging test.
No Microsoft installer binaries, guest setup boot, physical devices or WIM extraction.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

cli = Path(sys.argv[1] if len(sys.argv) > 1 else "agent/target/debug/bootnexa-media").resolve()
assert cli.is_file(), f"Build native CLI first: {cli}"
with tempfile.TemporaryDirectory(prefix="bootnexa-windows-virtual-") as directory:
    root = Path(directory)
    efi = root / "FAKE-BOOTX64.EFI"
    pe = bytearray(512)
    pe[:2] = b"MZ"
    pe[0x3c:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\0\0"
    pe[0x84:0x86] = (0x8664).to_bytes(2, "little")
    pe[0x98:0x9a] = (0x20b).to_bytes(2, "little")
    pe[0x98+68:0x98+70] = (10).to_bytes(2, "little")
    efi.write_bytes(pe)
    source = root / "synthetic-windows-candidate.iso"
    generator = Path("tests/virtual-media/create-iso-fixture.py")
    subprocess.run([sys.executable, str(generator), str(efi), str(source),
                    "--profile", "windows-preflight"], check=True)
    original_digest = hashlib.file_digest(source.open("rb"), "sha256").hexdigest()

    def run(operation, path=source, dest=root):
        cmd = [str(cli), operation, str(path)]
        if operation == "stage-windows-virtual-cdrom":
            cmd.append(str(dest))
        return subprocess.run(cmd, text=True, capture_output=True)

    def reject(label, offset, bad_bytes):
        bad = root / f"reject-{label}.iso"
        with source.open("rb") as original, bad.open("wb") as changed:
            changed.write(original.read())
        with bad.open("r+b") as handle:
            handle.seek(offset)
            handle.write(bad_bytes)
        before = set(root.glob("bootnexa-windows-virtual-cdrom-*.iso"))
        result = run("stage-windows-virtual-cdrom", bad)
        assert result.returncode != 0, f"{label} incorrectly staged: {result.stdout}"
        assert set(root.glob("bootnexa-windows-virtual-cdrom-*.iso")) == before
        print(f"PASS reject {label}: {result.stderr.strip()[:100]}")

    report = run("inspect-windows-iso")
    assert report.returncode == 0, report.stderr
    result = json.loads(report.stdout)
    assert result["readOnly"] and not result["physicalWriteAuthorized"]
    assert not result["windowsSetupBootVerified"] and not result["windowsVersionVerified"]
    assert result["virtualCdromStagingEligible"]
    assert result["x64EfiLoaderHeaderValid"] and result["setupExeObserved"]
    assert result["bootWim"]["imageCount"] == result["installWim"]["imageCount"] == 1
    assert not result["wimSplitImplemented"] and not result["udfTranslationSupported"]
    print("PASS bounded Windows-like ISO9660 metadata and WIM header inspection")

    stage = run("stage-windows-virtual-cdrom")
    assert stage.returncode == 0, stage.stderr
    receipt = json.loads(stage.stdout)
    exported = Path(receipt["outputPath"])
    assert exported.is_file() and exported.suffix == ".iso" and exported.parent == root
    assert exported.stat().st_size == source.stat().st_size
    assert receipt["outputSha256"] == original_digest
    assert hashlib.file_digest(exported.open("rb"), "sha256").hexdigest() == original_digest
    assert not receipt["physicalWriteAuthorized"] and not receipt["windowsSetupBootVerified"]
    assert hashlib.file_digest(source.open("rb"), "sha256").hexdigest() == original_digest
    print("PASS 64KiB-bounded virtual CD-ROM bit-exact staging and independent read-back SHA-256")

    reject("boot-wim-signature", 61*2048, b"NOTWIM00")
    reject("install-wim-signature", 62*2048, b"NOTWIM00")
    reject("spanned-wim", 61*2048+42, (2).to_bytes(2, "little"))
    reject("zero-wim-images", 62*2048+44, (0).to_bytes(4, "little"))
    reject("invalid-efi-loader", 64*2048, b"ZZ")

    udf = root / "udf-vrs.iso"
    udf.write_bytes(source.read_bytes())
    with udf.open("r+b") as changed:
        for lba, label in [(19, b"BEA01"), (20, b"NSR03"), (21, b"TEA01")]:
            changed.seek(lba*2048)
            changed.write(bytes([0]) + label)
    report = run("inspect-windows-iso", udf)
    assert report.returncode == 0, report.stderr
    udf_report = json.loads(report.stdout)
    assert udf_report["udfSignatureObserved"] and not udf_report["virtualCdromStagingEligible"]
    assert udf_report["fat32InstallPayloadCompatible"] is None
    assert run("stage-windows-virtual-cdrom", udf).returncode != 0
    print("PASS UDF recognition remains staging-disabled without validated UDF traversal")

    incomplete = root / "incomplete.iso"
    subprocess.run([sys.executable, str(generator), str(efi), str(incomplete),
                    "--profile", "windows"], check=True)
    incomplete_report = run("inspect-windows-iso", incomplete)
    # Truncated/WIM-less image must not be staged; preflight may reject it entirely.
    if incomplete_report.returncode == 0:
        assert not json.loads(incomplete_report.stdout)["virtualCdromStagingEligible"]
    assert run("stage-windows-virtual-cdrom", incomplete).returncode != 0
    print("PASS incomplete installer fixture fails closed")

    symlink = root / "symlink-parent"
    symlink.symlink_to(root, target_is_directory=True)
    assert run("stage-windows-virtual-cdrom", source, symlink).returncode != 0
    print("PASS symlink destination parent rejected")

    large = root / "large-iso9660-metadata.iso"
    with source.open("rb") as original, large.open("wb") as candidate:
        candidate.write(original.read())
        candidate.truncate(70*1024*1024)
    # Rewrite the INSTALL.WIM directory entry to a disjoint sparse 64 MiB
    # extent. This tests metadata-only planning, not installer validity.
    with large.open("rb") as f:
        data = f.read(26*2048+2048)
    entry = data.find(b"INSTALL.WIM;1", 26*2048)
    assert entry != -1
    start = entry - 33
    with large.open("r+b") as handle:
        handle.seek(start+2)
        handle.write((128).to_bytes(4, "little")+(128).to_bytes(4, "big"))
        handle.seek(start+10)
        handle.write((64*1024*1024).to_bytes(4, "little")+(64*1024*1024).to_bytes(4, "big"))
        handle.seek(128*2048)
        handle.write(source.read_bytes()[62*2048:62*2048+208])
    large_report = run("inspect-windows-iso", large)
    assert large_report.returncode == 0, large_report.stderr
    lr = json.loads(large_report.stdout)
    assert lr["installWim"]["fileBytes"] == 64*1024*1024
    assert not lr["windowsSetupBootVerified"] and lr["virtualCdromStagingEligible"]
    assert run("plan-iso", large).returncode != 0  # old extraction cap is immutable
    print("PASS 64 MiB sparse WIM header inspected without widening EFI extraction limits")

print("PASS Phase 8 synthetic Windows ISO safety/inspection/staging qualification")
