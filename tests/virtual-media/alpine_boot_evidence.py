#!/usr/bin/env python3
"""CI-only evidence for a pinned Alpine ISO booted in virtual QEMU/OVMF.

A native CLI report is *not* boot evidence. This tool fails closed until the
actual emulator serial log contains a Linux login prompt and the exported
regular-file image is independently read back, without modifying any disk.
The receipt is a CI observation, not a signed attestation or USB qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PROFILE = "alpine-virt-3.24.2-x86_64"
EXPECTED_SHA256 = "3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b"
EXPECTED_BYTES = 69_206_016
MAX_SERIAL_BYTES = 4 * 1024 * 1024
LOGIN_PROMPT = re.compile(rb"(?:alpine|localhost)[ \t]+login:", re.IGNORECASE)


def sha256_regular_file(path: Path, expected_size: int | None = None) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("evidence input must be an ordinary, non-symlink file")
    if expected_size is not None and path.stat().st_size != expected_size:
        raise ValueError("evidence input has unexpected byte length")
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_native_report(report: dict, exported: Path) -> None:
    if type(report) is not dict or type(report.get("media")) is not dict:
        raise ValueError("native report or media envelope absent")
    media = report["media"]
    required_true = ("publisherSha256Matched", "mbrEfiPartitionVerified", "fatEfiBootloaderVerified")
    if (report.get("virtualOnly") is not True
            or report.get("physicalWriteAuthorized") is not False
            or media.get("virtualOnly") is not True
            or media.get("physicalWriteAuthorized") is not False
            or media.get("bootExecutionVerified") is not False
            or media.get("linuxDistributionBootVerified") is not False
            or not all(media.get(key) is True for key in required_true)):
        raise ValueError("native report claimed physical authority/boot success or missed a gate")
    if (media.get("distroProfile") != PROFILE
            or type(media.get("imageBytes")) is not int
            or media["imageBytes"] != EXPECTED_BYTES
            or media.get("sourceSha256") != EXPECTED_SHA256
            or media.get("copiedSha256") != EXPECTED_SHA256
            or report.get("outputSha256") != EXPECTED_SHA256
            or report.get("outputPath") != str(exported)):
        raise ValueError("native report does not match exact publisher-pinned image")


def serial_login_verified(data: bytes) -> bool:
    # Serial output belongs only to the ephemeral, network-disabled QEMU guest.
    return bool(LOGIN_PROMPT.search(data))


def produce_evidence(report_path: Path, serial_path: Path, firmware: Path,
                     output_directory: Path, revision: str) -> dict:
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError("native report is not a regular file")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    exported = Path(report.get("outputPath", ""))
    validate_native_report(report, exported)
    if sha256_regular_file(exported, EXPECTED_BYTES) != EXPECTED_SHA256:
        raise ValueError("exported image changed after QEMU boot or hash mismatch")
    if serial_path.is_symlink() or not serial_path.is_file():
        raise ValueError("missing serial log from real QEMU execution")
    if serial_path.stat().st_size > MAX_SERIAL_BYTES:
        raise ValueError("serial log exceeds bounded evidence limit")
    serial = serial_path.read_bytes()
    if not serial_login_verified(serial):
        raise ValueError("Alpine Linux serial login was not observed")
    # Distro OVMF package paths can legitimately be symlinks to versioned firmware.
    firmware_digest = sha256_regular_file(firmware.resolve(strict=True))
    qemu_version = subprocess.check_output(
        ["qemu-system-x86_64", "--version"], text=True, timeout=5
    ).splitlines()[0]
    if not revision or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("commit identity is missing or malformed")
    if output_directory.is_symlink() or not output_directory.is_dir():
        raise ValueError("evidence destination must be an existing real directory")
    evidence = {
        "schemaVersion": 1,
        "verificationClass": "ci-virtual-boot-observation",
        "sourceRevision": revision,
        "profile": PROFILE,
        "imageBytes": EXPECTED_BYTES,
        "sourceSha256": EXPECTED_SHA256,
        "outputSha256": EXPECTED_SHA256,
        "readbackVerified": True,
        "firmware": "OVMF",
        "firmwareSha256": firmware_digest,
        "qemuVersion": qemu_version,
        "bootTarget": "Linux serial login prompt",
        "bootExecutionVerified": True,
        "linuxDistributionBootVerified": True,
        "virtualOnly": True,
        "physicalWriteAuthorized": False,
        "physicalUsbBootVerified": False,
        "secureBootVerified": False,
        "serialLogSha256": hashlib.sha256(serial).hexdigest(),
        "serialLogBytes": len(serial),
    }
    dest = output_directory / "alpine-boot-evidence.json"
    # No paths, tokens or guest image contents in the published receipt.
    temp = output_directory / f".alpine-evidence-{os.getpid()}.tmp"
    try:
        with temp.open("x", encoding="utf-8") as fp:
            json.dump(evidence, fp, indent=2, sort_keys=True)
            fp.write("\n")
        # Hard-link publication is atomic and refuses to replace stale receipts.
        os.link(temp, dest)
    finally:
        temp.unlink(missing_ok=True)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--serial", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    evidence = produce_evidence(args.report, args.serial, args.firmware,
                                args.evidence_dir, args.revision)
    print(f"PASS: CI-only QEMU/OVMF Linux login evidence: {evidence['profile']}")


if __name__ == "__main__":
    main()
