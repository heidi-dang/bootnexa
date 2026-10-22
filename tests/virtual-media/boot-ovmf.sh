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
timeout 55s qemu-system-x86_64 \
  -machine q35 -accel tcg -m 256 \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,unit=1,file=$tmp/VARS.fd" \
  -drive "id=media,if=none,format=raw,readonly=on,file=$image" \
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
