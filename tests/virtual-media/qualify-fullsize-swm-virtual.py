#!/usr/bin/env python3
"""Opt-in >4 GiB WIM->SWM->anonymous GPT/FAT32 qualification.

No source bytes leave the host; no raw devices or persistent virtual images.
A local unmodified source and operator-supplied SHA-256 are prerequisites.
The SHA is NOT Microsoft publisher attestation or Windows Setup boot proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

GIB = 1024**3
MAX_SOURCE = 16 * GIB
MAX_SPLIT = 16 * GIB
MAX_FAT32_FILE = 2**32 - 1
def selected_cli_build(profile):
    if profile not in ("debug", "release"):
        raise Refused("unsupported native media build profile")
    return Path(f"agent/target/{profile}/bootnexa-media").resolve()


CLI = selected_cli_build(os.environ.get("BOOTNEXA_MEDIA_PROFILE", "debug"))


class Refused(ValueError):
    pass


def safe_regular(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise Refused("source must be a regular non-symlink file")
    return path.resolve(strict=True)


def safe_directory(path):
    path = Path(path)
    if not path.is_dir() or path.is_symlink():
        raise Refused("scratch parent must be a real non-symlink directory")
    return path.resolve(strict=True)


def sha256(path):
    sha = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            sha.update(chunk)
    return sha.hexdigest()


def validate_scratch_budget(source_bytes, available, capacity):
    if type(source_bytes) is not int or not 4*GIB < source_bytes <= MAX_SOURCE:
        raise Refused("full-size WIM must be >4 GiB and <=16 GiB")
    if type(capacity) is not int or not 8 <= capacity <= 24:
        raise Refused("virtual disk must be 8-24 GiB")
    if type(available) is not int or available < 0:
        raise Refused("invalid scratch availability")
    # Three media-sized copies (SWM, anonymous FAT32, miscellaneous
    # overhead) plus 3 GiB. The host free-space gate remains authoritative.
    required = 3*source_bytes + 3*GIB
    if available < required:
        raise Refused("insufficient operator scratch bytes for full-size qualification")
    return required


def run(argv, *, env=None, timeout=3600):
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, start_new_session=True)
    try:
        stdout, _ = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        # Linux-only qualification: kill the entire dedicated process group,
        # including wimlib grandchildren, rather than orphaning a split job.
        os.killpg(child.pid, signal.SIGKILL)
        child.communicate()
        raise Refused("native qualification exceeded operator timeout") from exc
    if child.returncode != 0 or len(stdout) > 2*1024*1024:
        raise Refused("native qualification step rejected the source or exceeded report budget")
    try:
        return json.loads(stdout)
    except ValueError as exc:
        raise Refused("invalid native receipt") from exc


def qualify(source, expected, scratch_parent, disk_gib=16, part_mib=3800):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise Refused("expected SHA-256 must be exactly 64 hex characters")
    if not isinstance(part_mib, int) or not 1 <= part_mib <= 3800:
        raise Refused("invalid wimlib split size")
    source = safe_regular(source)
    scratch_parent = safe_directory(scratch_parent)
    if not CLI.is_file():
        raise Refused("read-only native BootNexa CLI has not been built")
    size = source.stat().st_size
    stats = os.statvfs(scratch_parent)
    available = stats.f_bavail * stats.f_frsize
    required = validate_scratch_budget(size, available, disk_gib)
    before = sha256(source)
    if before != expected.lower():
        raise Refused("source WIM SHA-256 does not match operator-provided digest")
    print("FULLSIZE: source SHA-256 verified; splitting format-valid WIM", file=sys.stderr, flush=True)
    # Only the newly created scratch tree is removed on exit/failure.
    # No pre-existing files in scratch_parent are modified.
    with tempfile.TemporaryDirectory(prefix="bootnexa-optin-fullsize-", dir=scratch_parent) as td:
        env = os.environ.copy()
        env["TMPDIR"] = td
        split = run([str(CLI), "split-wim-virtual", str(source),
                     td, str(part_mib)], env=env)
        if (split.get("sourceSha256") != before or
                split.get("splitWimIntegrityVerified") is not True or
                split.get("physicalWriteAuthorized") is not False):
            raise Refused("WIM split receipt was inconsistent")
        parts = split.get("parts")
        if not isinstance(parts, list) or not 2 <= len(parts) <= 64:
            raise Refused("unexpected SWM part count")
        total = 0
        for index, part in enumerate(parts, 1):
            filename = "install.swm" if index == 1 else f"install{index}.swm"
            if (part.get("filename") != filename or
                    type(part.get("bytes")) is not int or
                    not 0 < part["bytes"] <= MAX_FAT32_FILE or
                    not re.fullmatch("[a-f0-9]{64}", part.get("sha256", ""))):
                raise Refused("invalid SWM manifest part")
            total += part["bytes"]
        if total <= 4*GIB:
            raise Refused("actual SWM payload is not greater than 4 GiB")
        if total > MAX_SPLIT:
            raise Refused("split archive exceeds 16 GiB staging budget")
        print("FULLSIZE: archive split and manifest verified; staging to anonymous FAT32", file=sys.stderr, flush=True)
        split_dir = Path(split["outputDirectory"])
        if split_dir.parent != Path(td) or split_dir.is_symlink():
            raise Refused("untrusted SWM split output directory")
        # Rust re-verifies the complete archive, source SHA values, host
        # storage admission and independent FAT32 readback.
        receipt = run([str(CLI), "stage-fullsize-windows-swm-virtual",
                       str(disk_gib), str(split_dir),
                       "--experimental-virtual-only"], env=env)
        if (receipt.get("fullSizeVirtualProfileRequested") is not True or
                receipt.get("hostStorageAdmissionPassed") is not True or
                receipt.get("gptIntegrityVerified") is not True or
                receipt.get("payloadFat32Verified") is not True or
                receipt.get("stagedParts") != parts or
                receipt.get("totalStagedBytes") != total):
            raise Refused("full-size virtual receipt did not prove SWM transfer")
        for key in ("physicalWriteAuthorized", "windowsSetupBootVerified",
                    "installerCompatibleVerified", "fullDiskSha256Verified",
                    "persistentDiskImageProduced"):
            if receipt.get(key) is not False:
                raise Refused("unsupported installation claim")
        if sha256(source) != before:
            raise Refused("WIM source changed during staged transfer")
        print("FULLSIZE: independent FAT32 SHA-256 and unchanged source verified", file=sys.stderr, flush=True)
        return {
            "schema": "bootnexa-optin-fullsize-swm-virtual-v1",
            "syntheticOrOperatorSuppliedWimSha256": before,
            "sourceBytes": size,
            "splitPartCount": len(parts),
            "splitBytes": total,
            "virtualNominalGiB": disk_gib,
            "scratchRequiredBytesAtPreflight": required,
            "verifiedReadback": True,
            "publisherProvenanceVerified": False,
            "windowsSetupBootVerified": False,
            "installerCompatibleVerified": False,
            "fullDiskSha256Verified": False,
            "physicalWriteAuthorized": False,
            "persistentDiskImageProduced": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--scratch-parent", type=Path, required=True)
    parser.add_argument("--disk-gib", type=int, default=16)
    parser.add_argument("--part-mib", type=int, default=3800)
    args = parser.parse_args()
    try:
        result = qualify(args.source, args.expected_sha256, args.scratch_parent,
                         args.disk_gib, args.part_mib)
    except (Refused, OSError, subprocess.SubprocessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
