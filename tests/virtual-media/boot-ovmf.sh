#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
rustup target add x86_64-unknown-uefi
rustc --edition=2024 --target x86_64-unknown-uefi -C panic=abort -C opt-level=s tests/fixtures/bootnexa-uefi-marker.rs -o "$tmp/BOOTX64.EFI"
cargo build --locked --release --manifest-path agent/Cargo.toml --bin bootnexa-media
agent/target/release/bootnexa-media build-virtual "$tmp/BOOTX64.EFI" "$tmp" gpt > "$tmp/report.json"
python3 - "$tmp/report.json" "$tmp" <<'PY'
import json,sys,pathlib
report=json.load(open(sys.argv[1]))
assert report["virtualOnly"] and not report["physicalWriteAuthorized"]
assert report["media"]["fat32Verified"] and report["media"]["fullPartitionTableVerified"]
assert not report["media"]["bootExecutionVerified"]
p=pathlib.Path(report["outputPath"])
assert p.parent == pathlib.Path(sys.argv[2]) and p.name.startswith("bootnexa-virtual-")
assert p.stat().st_size == 96 * 1024 * 1024
PY
image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["outputPath"])' "$tmp/report.json")"
if ! command -v qemu-system-x86_64 >/dev/null; then
  echo "qemu-system-x86_64 unavailable: virtual boot cannot be qualified"
  exit 1
fi
code=""
vars=""
for base in /usr/share/OVMF /usr/share/ovmf; do
  for candidate in "$base/OVMF_CODE_4M.fd" "$base/OVMF_CODE.fd"; do
    if [[ -f "$candidate" ]]; then code="$candidate";break;fi
  done
  for candidate in "$base/OVMF_VARS_4M.fd" "$base/OVMF_VARS.fd"; do
    if [[ -f "$candidate" ]]; then vars="$candidate";break;fi
  done
  if [[ -n "$code" && -n "$vars" ]]; then break;fi
done
if [[ -z "$code" || -z "$vars" ]]; then echo "OVMF firmware is absent"; exit 1;fi
cp "$vars" "$tmp/VARS.fd"
status=0
# snapshot=on creates a temporary COW layer, so the base image is never mutated.
timeout 55s qemu-system-x86_64 \
  -machine q35 -accel tcg -m 256 \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,unit=1,file=$tmp/VARS.fd" \
  -drive "id=media,if=none,format=raw,snapshot=on,file=$image" \
  -device ich9-ahci,id=ahci \
  -device ide-hd,drive=media,bus=ahci.0 \
  -debugcon "file:$tmp/uefi-debug.log" -global isa-debugcon.iobase=0xe9 \
  -display none -monitor none -serial none -no-reboot -net none >"$tmp/qemu.log" 2>&1 || status=$?
if [[ "$status" != 0 && "$status" != 124 ]];then
  cat "$tmp/qemu.log";echo "QEMU stopped with unexpected result $status";exit 1
fi
if ! grep -aFq 'BOOTNEXA_UEFI_BOOT_OK' "$tmp/uefi-debug.log";then
  echo "UEFI boot marker missing; virtual boot NOT qualified"
  sed -n '1,80p' "$tmp/qemu.log"
  echo "debug output bytes: $(wc -c < "$tmp/uefi-debug.log")"
  exit 1
fi
echo 'PASS: freshly-generated GPT/FAT32 virtual media booted BOOTX64.EFI under OVMF in QEMU.'

# ISO -> validated directory extents -> bounded FAT32 virtual disk -> UEFI execution.
python3 tests/virtual-media/create-iso-fixture.py "$tmp/BOOTX64.EFI" "$tmp/source.iso"
agent/target/release/bootnexa-media plan-iso "$tmp/source.iso" > "$tmp/plan.json"
python3 - "$tmp/plan.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["plan"]["virtualEfiEligible"] and not x["physicalWriteAuthorized"]
assert [f["path"] for f in x["files"]] == ["EFI/BOOT/BOOTX64.EFI","README.TXT"]
assert not x["plan"]["windowsSetupVerified"] and not x["plan"]["linuxBootVerified"]
PY
agent/target/release/bootnexa-media build-from-iso "$tmp/source.iso" "$tmp" > "$tmp/iso-copy-report.json"
python3 - "$tmp/iso-copy-report.json" <<'PY'
import json, pathlib,sys
r=json.load(open(sys.argv[1]))
assert r["virtualOnly"] and r["media"]["fullPartitionTableVerified"]
assert not r["physicalWriteAuthorized"] and not r["media"]["bootExecutionVerified"]
assert r["media"]["sourceFiles"]==2 and r["media"]["verifiedFiles"]==2
assert pathlib.Path(r["outputPath"]).stat().st_size==96*1024*1024
PY
for profile in windows linux;do
  python3 tests/virtual-media/create-iso-fixture.py "$tmp/BOOTX64.EFI" "$tmp/$profile.iso" --profile "$profile"
  if agent/target/release/bootnexa-media build-from-iso "$tmp/$profile.iso" "$tmp" > "$tmp/$profile-unexpected.json" 2>/dev/null;then
    echo "ERROR: unqualified $profile installer candidate was silently converted"
    exit 1
  fi
  echo "PASS: incomplete $profile installation media blocked by compatibility planner"
done
image="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["outputPath"])' "$tmp/iso-copy-report.json")"
cp "$vars" "$tmp/ISO-VARS.fd"
status=0
timeout 55s qemu-system-x86_64 \
  -machine q35 -accel tcg -m 256 \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,unit=1,file=$tmp/ISO-VARS.fd" \
  -drive "id=media,if=none,format=raw,snapshot=on,file=$image" \
  -device ich9-ahci,id=ahci \
  -device ide-hd,drive=media,bus=ahci.0 \
  -debugcon "file:$tmp/iso-uefi-debug.log" -global isa-debugcon.iobase=0xe9 \
  -display none -monitor none -serial none -no-reboot -net none > "$tmp/iso-qemu.log" 2>&1 || status=$?
if [[ "$status" != 0 && "$status" != 124 ]];then
  cat "$tmp/iso-qemu.log"
  echo "ISO-derived QEMU virtual boot failed with status $status"
  exit 1
fi
if ! grep -aFq 'BOOTNEXA_UEFI_BOOT_OK' "$tmp/iso-uefi-debug.log";then
  cat "$tmp/iso-qemu.log"
  echo "ISO-derived virtual media failed UEFI marker check"
  exit 1
fi
echo "PASS: real ISO9660 traversal, two-file FAT32 copy/read-back, and UEFI boot in QEMU/OVMF."

# Separate strict dual-format ISO/GPT virtual-image boot gate.
bash tests/virtual-media/hybrid-ovmf.sh "$tmp" "$code" "$vars"
