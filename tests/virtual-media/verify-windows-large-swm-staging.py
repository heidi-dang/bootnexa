#!/usr/bin/env python3
"""288 MiB synthetic format-valid WIM -> verified SWM -> anonymous FAT32.

Opt-in CI only; no Microsoft bytes, physical devices or persisted disk images.
"""
import hashlib
import json
import os
import struct
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
    # The explicitly selected full-size profile shares the same verified
    # write/readback core. This 288 MiB smoke checks behavior but does NOT
    # attest a >4 GiB source, installer boot or publisher provenance.
    denied = run(AGENT, "stage-fullsize-windows-swm-virtual", "8", swm)
    assert denied.returncode != 0 and not denied.stdout.strip()
    denied = run(AGENT, "stage-fullsize-windows-swm-virtual", "7", swm,
                 "--experimental-virtual-only")
    assert denied.returncode != 0 and not denied.stdout.strip()
    full = run(AGENT, "stage-fullsize-windows-swm-virtual", "8", swm,
               "--experimental-virtual-only")
    assert full.returncode == 0, (full.stderr, full.stdout)
    large = json.loads(full.stdout)
    assert large["fullSizeVirtualProfileRequested"] is True
    assert large["persistentDiskImageProduced"] is False
    assert large["hostStorageAdmissionPassed"] is True
    assert large["stagedParts"] == parts
    assert large["totalStagedBytes"] == count
    assert large["payloadFat32Verified"] and large["gptIntegrityVerified"]
    for flag in ("physicalWriteAuthorized", "windowsSetupBootVerified",
                 "installerCompatibleVerified", "fullDiskSha256Verified"):
        assert large[flag] is False, flag
    assert not list(root.rglob("*.img")), "An output disk image was persisted"
    # Combine verified SWM and ALL synthetic installer-shaped ISO files on
    # the very same anonymous GPT/FAT32 disk. An independent small boot WIM
    # uses actual wimlib resources rather than a fake WIM header.
    boot_dir = root / "small-boot-fixture"
    boot_dir.mkdir()
    (boot_dir / "boot.txt").write_text("non-Microsoft synthetic WinPE fixture")
    boot_wim = root / "synthetic-boot.wim"
    small = run("wimlib-imagex", "capture", boot_dir, boot_wim, "Synthetic BOOT.WIM",
                "--compress=none")
    assert small.returncode == 0, small.stderr
    assert run("wimlib-imagex", "verify", boot_wim).returncode == 0
    pe = bytearray(512)
    pe[:2] = b"MZ"
    pe[0x3c:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\x00\x00"
    pe[0x84:0x86] = b"\x64\x86"
    pe[0x98:0x9a] = b"\x0b\x02"
    files = {
        "EFI/BOOT/BOOTX64.EFI": bytes(pe),
        "EFI/MICROSOFT/BOOT/BCD": b"BCD non-Microsoft test data",
        "SOURCES/BOOT.WIM": boot_wim.read_bytes(),
        "SETUP.EXE": bytes(pe),
        "BOOT/BOOT.SDI": b"synthetic boot.sdi",
        "BOOTMGR.EFI": bytes(pe),
        "SUPPORT/README.TXT": b"synthetic, no Setup compatibility assertions",
    }

    def framed_stream(items):
        frame = bytearray(b"BNXI0002" + struct.pack("<H", len(items)))
        for name, contents in items.items():
            raw = name.encode("ascii")
            frame.extend(struct.pack("<H", len(raw)) + raw +
                         struct.pack("<Q", len(contents)) +
                         bytes.fromhex(hashlib.sha256(contents).hexdigest()) + contents)
        return bytes(frame)

    frame = framed_stream(files)
    def run_combined(content=frame):
        return subprocess.run(
            [str(AGENT), "stage-combined-windows-tree-virtual", "8", str(swm),
             "--experimental-virtual-only"],
            input=content, capture_output=True, timeout=480)

    combined = run_combined()
    assert combined.returncode == 0, (combined.stderr.decode(), combined.stdout.decode())
    combined_receipt = json.loads(combined.stdout)
    assert combined_receipt["virtualCombinedLayoutVerified"] is True
    assert combined_receipt["efiFat32Verified"] and combined_receipt["payloadFat32Verified"]
    assert combined_receipt["gptIntegrityVerified"]
    assert combined_receipt["swm"]["stagedParts"] == parts
    assert combined_receipt["swm"]["totalStagedBytes"] == count
    assert combined_receipt["swm"]["hostStorageAdmissionPassed"] is True
    assert combined_receipt["isoFiles"]["stagedFileCount"] == len(files)
    assert combined_receipt["isoFiles"]["stagedBytes"] == sum(map(len, files.values()))
    iso_index = {file["path"]: file for file in combined_receipt["isoFiles"]["files"]}
    assert iso_index.keys() == files.keys()
    assert all(iso_index[name]["sha256"] == hashlib.sha256(value).hexdigest() and
               iso_index[name]["independentFat32ReadbackVerified"]
               for name, value in files.items())
    for flag in ("physicalWriteAuthorized", "windowsSetupBootVerified",
                 "installerCompatibleVerified", "fullDiskSha256Verified",
                 "persistentDiskImageProduced", "completeSourceIsoVerified"):
        assert combined_receipt[flag] is False, flag
    assert sha256(source) == original_wim
    assert all(sha256(swm / part["filename"]) == part["sha256"] for part in parts)
    assert not list(root.rglob("*.img"))
    print("PASS same anonymous 8GiB GPT/FAT32: verified SWM + 7 synthetic ISO files across ESP/payload, all independently read back")

    missing_confirm = subprocess.run(
        [str(AGENT), "stage-combined-windows-tree-virtual", "8", str(swm)],
        input=frame, capture_output=True, timeout=10)
    assert missing_confirm.returncode != 0 and not missing_confirm.stdout
    too_small = subprocess.run(
        [str(AGENT), "stage-combined-windows-tree-virtual", "7", str(swm),
         "--experimental-virtual-only"],
        input=frame, capture_output=True, timeout=10)
    assert too_small.returncode != 0 and not too_small.stdout
    print("PASS no-flag and too-small virtual layouts refused before staging")
    print("PASS explicitly gated full-size virtual profile on bounded SWM fixture; >4GiB actual scale remains tested separately")
    print(f"PASS format-valid synthetic {count // MIB} MiB SWM ({len(parts)} parts) staged in anonymous 2 GiB GPT/FAT32")
    print("PASS wimlib source validation, size admission, host-space admission, FAT32 SHA readback, unchanged inputs, no physical writes")
