#!/usr/bin/env python3
"""Fail CI if any pinned Alpine profile drifts across Rust/browser/CI/evidence."""
import re
from pathlib import Path

rust = Path("agent/src/alpine_iso.rs").read_text()
browser = Path("src/known-linux-images.ts").read_text()
ci = Path("tests/virtual-media/alpine-virt-ovmf.sh").read_text()
evidence = Path("tests/virtual-media/alpine_boot_evidence.py").read_text()

def require(pattern: str, text: str) -> str:
    value = re.search(pattern, text, re.S | re.M)
    if not value:
        raise SystemExit(f"Missing exact profile contract: {pattern}")
    return value.group(1)

profiles = (
    ("3.24.2", "ALPINE_VIRT_3242", "VERIFIED_ALPINE_VERSION", "VERIFIED_SHA256", "VERIFIED_SIZE", "PROFILE", "EXPECTED_SHA256", "EXPECTED_BYTES"),
    ("3.24.1", "ALPINE_VIRT_3241", "VERIFIED_ALPINE_3241_VERSION", "VERIFIED_ALPINE_3241_SHA256", "VERIFIED_ALPINE_3241_SIZE", "PROFILE_3241", "EXPECTED_SHA256_3241", "EXPECTED_BYTES_3241"),
)
for version, ui_key, rust_version, rust_hash, rust_size, ev_profile, ev_hash, ev_size in profiles:
    expected_name = f"alpine-virt-{version}-x86_64"
    native_name = require(rf'pub const {rust_version}: &str = "([^"]+)"', rust)
    native_hash = require(rf'pub const {rust_hash}: &str =\s*"([a-f0-9]{{64}})"', rust)
    native_size = int(require(rf'const {rust_size}: u64 = ([0-9_]+)', rust).replace("_", ""))
    section = require(rf'export const {ui_key} = \{{(.*?)\}} as const;', browser)
    ui_name = require(r"profile: '([^']+)'", section)
    ui_hash = require(r"sha256: '([a-f0-9]{64})'", section)
    ui_size = int(require(r'imageBytes: (\d+)', section))
    ci_hash = require(rf'{re.escape(version) }\) digest="([a-f0-9]{{64}})"', ci)
    receipt_profile = require(rf'^{ev_profile} = "([^"]+)"', evidence)
    receipt_hash = require(rf'^{ev_hash} = "([a-f0-9]{{64}})"', evidence)
    receipt_size = int(require(rf'^{ev_size} = ([0-9_]+)', evidence).replace("_", ""))
    assert native_name == ui_name == receipt_profile == expected_name, f"Profile version drift: {version}"
    assert native_hash == ui_hash == ci_hash == receipt_hash, f"SHA-256 drift: {version}"
    assert native_size == ui_size == receipt_size, f"Image byte size drift: {version}"
    print(f"PASS: {expected_name} exact SHA-256, size and name consistent across Rust/browser/CI/evidence")
