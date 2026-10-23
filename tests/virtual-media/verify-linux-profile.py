#!/usr/bin/env python3
"""Ensure frontend's exact-version Linux whitelist cannot drift from native or CI."""
import re
from pathlib import Path

rust=Path("agent/src/alpine_iso.rs").read_text()
browser=Path("src/known-linux-images.ts").read_text()
ci=Path("tests/virtual-media/alpine-virt-ovmf.sh").read_text()

def require(pattern: str, content: str) -> str:
    match=re.search(pattern,content)
    if not match:
        raise SystemExit(f"Missing Alpine profile contract pattern: {pattern}")
    return match.group(1)

rust_hash=require(r'pub const VERIFIED_SHA256:\s*&str\s*=\s*"([a-f0-9]{64})"',rust)
ui_hash=require(r"sha256:\s*'([a-f0-9]{64})'",browser)
ci_hash=require(r'digest="([a-f0-9]{64})"',ci)
assert rust_hash==ui_hash==ci_hash,"Alpine publisher digests drifted between native, browser and CI"

rust_name=require(r'pub const VERIFIED_ALPINE_VERSION:\s*&str\s*=\s*"([^"]+)"',rust)
ui_name=require(r"profile:\s*'([^']+)'",browser)
assert rust_name==ui_name,"Alpine version drifted between native and browser"

rust_size=int(require(r'const VERIFIED_SIZE:\s*u64\s*=\s*([0-9_]+)',rust).replace('_',''))
ui_size=int(require(r'imageBytes:\s*(\d+)',browser))
assert rust_size==ui_size,"Alpine size drifted between native and browser"
print("PASS: exact SHA-256, profile and byte size consistent across native, browser and CI")
