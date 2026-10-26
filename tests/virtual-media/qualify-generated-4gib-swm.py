#!/usr/bin/env python3
"""Operator-only >4 GiB generated synthetic WIM -> SWM -> anonymous FAT32 proof.

No Microsoft bytes, network, raw devices, persistent image or production media.
Requires dedicated non-tmpfs scratch space; generates several GiB and runs
wimlib + the native virtual-only BootNexa CLI. Excluded from routine CI.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

MIB = 1024**2
GIB = 1024**3
CHUNK_MIB = 256
MIN_MIB = 4097
MAX_MIB = 6144
DEPENDENCY = Path(__file__).with_name("qualify-fullsize-swm-virtual.py")
spec = importlib.util.spec_from_file_location("bootnexa_fullsize_qualifier", DEPENDENCY)
qualifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualifier)


def file_plan(total_mib):
    if type(total_mib) is not int or not MIN_MIB <= total_mib <= MAX_MIB:
        raise qualifier.Refused("synthetic data size must be >4096 and <=6144 MiB")
    pieces = [CHUNK_MIB] * (total_mib // CHUNK_MIB)
    if total_mib % CHUNK_MIB:
        pieces.append(total_mib % CHUNK_MIB)
    return pieces


def scratch_requirement(total_bytes):
    """Budget original random files, WIM, split SWMs, anonymous FAT32 plus margin."""
    if type(total_bytes) is not int or not MIN_MIB*MIB <= total_bytes <= MAX_MIB*MIB:
        raise qualifier.Refused("invalid synthetic generation budget")
    return total_bytes * 4 + 6*GIB


def capture_synthetic_wim(source_directory, destination, env):
    process = subprocess.Popen(
        ["wimlib-imagex", "capture", str(source_directory), str(destination),
         "BootNexa non-proprietary synthetic full-size fixture", "--compress=none"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=1800)
    except subprocess.TimeoutExpired as exc:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise qualifier.Refused("synthetic wimlib capture exceeded 30-minute deadline") from exc
    if process.returncode != 0 or len(stdout) > MIB or len(stderr) > MIB:
        raise qualifier.Refused("synthetic wimlib capture failed or exceeded log budget")


def run(scratch_parent, total_mib):
    parent = qualifier.safe_directory(scratch_parent)
    plan = file_plan(total_mib)
    planned_bytes = total_mib * MIB
    stats = os.statvfs(parent)
    available = stats.f_bavail * stats.f_frsize
    required = scratch_requirement(planned_bytes)
    if available < required:
        raise qualifier.Refused("insufficient scratch filesystem space for generated >4 GiB fixture")
    if os.environ.get("BOOTNEXA_MEDIA_PROFILE") != "release":
        raise qualifier.Refused("actual >4 GiB qualification requires BOOTNEXA_MEDIA_PROFILE=release")
    if not qualifier.CLI.is_file():
        raise qualifier.Refused("BootNexa optimized native CLI is not built")
    start = time.monotonic()
    print("QUALIFICATION: scratch admitted; generating nonproprietary >4GiB inputs", file=sys.stderr, flush=True)
    with tempfile.TemporaryDirectory(prefix="bootnexa-synthetic-4gib-", dir=parent) as dirname:
        root = Path(dirname)
        inputs = root / "synthetic-files"
        inputs.mkdir()
        for index, mib in enumerate(plan):
            with (inputs / f"fixture-{index:02d}.bin").open("xb") as output:
                for _ in range(mib):
                    output.write(os.urandom(MIB))
        print("QUALIFICATION: synthetic source files complete; capturing real WIM", file=sys.stderr, flush=True)
        source = root / "generated-install.wim"
        env = os.environ.copy()
        env["TMPDIR"] = str(root)
        capture_synthetic_wim(inputs, source, env)
        source_size = source.stat().st_size
        if not 4*GIB < source_size <= 16*GIB:
            raise qualifier.Refused("captured WIM did not exceed actual 4 GiB source threshold")
        digest = qualifier.sha256(source)
        print("QUALIFICATION: >4GiB WIM verified; splitting and staging on anonymous FAT32", file=sys.stderr, flush=True)
        receipt = qualifier.qualify(source, digest, root, disk_gib=8, part_mib=3800)
        if receipt["splitBytes"] <= 4*GIB or receipt["verifiedReadback"] is not True:
            raise qualifier.Refused("real >4 GiB SWM bytes were not independently read back")
        print("QUALIFICATION: independent FAT32 SHA-256 readback passed; cleaning scratch", file=sys.stderr, flush=True)
        return {
            "schema": "bootnexa-generated-synthetic-fullsize-qualification-v1",
            "realDataBytesGenerated": planned_bytes,
            "formatValidWimBytes": source_size,
            "formatValidWimSha256": digest,
            "swmBytesIndependentlyReadBack": receipt["splitBytes"],
            "swmPartCount": receipt["splitPartCount"],
            "scratchBudgetRequiredBytes": required,
            "scratchAvailableAtAdmissionBytes": available,
            "virtualDiskNominalGiB": 8,
            "durationSeconds": round(time.monotonic()-start, 2),
            "fullSizeSwmReadbackVerified": True,
            "microsoftPublisherProvenanceVerified": False,
            "installerCompatibleVerified": False,
            "windowsSetupBootVerified": False,
            "physicalWriteAuthorized": False,
            "persistentDiskImageProduced": False,
            "temporaryScratchRemovedAfterCompletion": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--size-mib", type=int, default=4352)
    parser.add_argument("--confirm-generate-over-4gib", action="store_true")
    args = parser.parse_args()
    if not args.confirm_generate_over_4gib:
        parser.error("--confirm-generate-over-4gib must be explicitly supplied")
    try:
        result = run(args.scratch_parent, args.size_mib)
    except (qualifier.Refused, OSError, subprocess.SubprocessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
