#!/usr/bin/env python3
"""288 MiB synthetic format-valid WIM -> verified SWM -> anonymous FAT32.

Opt-in CI only; no Microsoft bytes, physical devices or persisted disk images.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

MIB = 1024 * 1024
TOTAL = 288 * MIB
AGENT = Path("agent/target/debug/bootnexa-media").resolve()
assert AGENT.is_file(), "Build read-only native media binary first"


def run(*argv):
    return subprocess.run([str(x) for x in argv], capture_output=True,
                          text=True, timeout=480)


def sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


with tempfile.TemporaryDirectory(prefix="bootnexa-large-swm-ci-") as tmp:
    root = Path(tmp)
    source_files = root / "synthetic"
    source_files.mkdir()
    # Twelve bounded independent sources avoid a single oversized,
    # indivisible WIM resource. Never place proprietary media in CI.
    for index in range(12):
        target = source_files / f"synthetic-{index:02}.bin"
        with target.open("wb") as output:
            for _ in range(24):
                output.write(os.urandom(MIB))
    original = {p.name: sha256(p) for p in source_files.iterdir()}
    source = root / "synthetic-install.wim"
    capture = run("wimlib-imagex", "capture", source_files, source,
                  "BootNexa synthetic large image", "--compress=none")
    assert capture.returncode == 0, capture.stderr
    assert run("wimlib-imagex", "verify", source).returncode == 0
    original_wim = sha256(source)

    split = run(AGENT, "split-wim-virtual", source, root, "128")
    assert split.returncode == 0, (split.stderr, split.stdout)
    details = json.loads(split.stdout)
    assert details["splitWimIntegrityVerified"] is True
    assert details["sourceSha256"] == original_wim
    assert not details["physicalWriteAuthorized"]
    swm = Path(details["outputDirectory"])
    parts = details["parts"]
    assert len(parts) >= 2
    count = sum(p["bytes"] for p in parts)
    assert count > 256 * MIB, count
    assert max(p["bytes"] for p in parts) > 64 * MIB
    assert max(p["bytes"] for p in parts) <= 512 * MIB
    for p in parts:
        assert sha256(swm / p["filename"]) == p["sha256"]

    stage = run(AGENT, "stage-large-windows-swm-demo", "2", swm)
    assert stage.returncode == 0, (stage.stderr, stage.stdout)
    receipt = json.loads(stage.stdout)
    assert receipt["virtualOnly"] is True
    assert receipt["splitArchivePreverified"] is True
    assert receipt["hostStorageAdmissionPassed"] is True
    assert receipt["availableHostBytesAtAdmission"] >= receipt["requiredFreeHostBytesAtAdmission"]
    assert receipt["payloadFat32Verified"] and receipt["gptIntegrityVerified"]
    assert receipt["totalStagedBytes"] == count
    assert receipt["stagedParts"] == parts
    for flag in ("physicalWriteAuthorized", "windowsSetupBootVerified",
                 "installerCompatibleVerified", "fullDiskSha256Verified"):
        assert receipt[flag] is False, flag
    assert sha256(source) == original_wim
    assert {p.name: sha256(p) for p in source_files.iterdir()} == original
    assert all(sha256(swm / p["filename"]) == p["sha256"] for p in parts)
    assert not list(root.rglob("*.img")), "An output disk image was persisted"
    print(f"PASS format-valid synthetic {count // MIB} MiB SWM ({len(parts)} parts) staged in anonymous 2 GiB GPT/FAT32")
    print("PASS wimlib source validation, size admission, host-space admission, FAT32 SHA readback, unchanged inputs, no physical writes")
