#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
alpine_version="${1:-3.24.2}"
case "$alpine_version" in
  3.24.2) digest="3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b" ;;
  3.24.1) digest="e73a6241bd5f3c5c2d4d38c02cc52c378c0415a7c888bd292066bf36e0f41a39" ;;
  *) echo "Unsupported non-pinned Alpine ISO: $alpine_version" >&2; exit 1 ;;
esac
# Retain bounded CI-only emulator evidence outside the disposable image folder.
evidence_dir="${BOOTNEXA_EVIDENCE_DIR:-test-results/alpine-virtual-boot/$alpine_version}"
mkdir -p "$evidence_dir"
if [[ -L "$evidence_dir" ]]; then echo "Refusing symlink evidence directory"; exit 1; fi
if [[ -e "$evidence_dir/alpine-boot-evidence.json" || -L "$evidence_dir/alpine-boot-evidence.json" ]]; then
  echo "Refusing stale success evidence: use a fresh evidence directory"; exit 1
fi
qemu_pid=''
cleanup() {
  if [[ -n "$qemu_pid" ]]; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  # Real vendor-ISO CI logs, never a user ISO or physical-device contents.
  for log in alpine-serial.log qemu.log ovmf-debug.log; do
    if [[ -f "$tmp/$log" && ! -L "$tmp/$log" ]]; then
      head -c 4194304 "$tmp/$log" > "$evidence_dir/$log" || true
    fi
  done
  rm -rf "$tmp"
}
trap cleanup EXIT
alpine="alpine-virt-${alpine_version}-x86_64.iso"
url="https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/$alpine"
curl -fLsS --retry 3 --connect-timeout 15 --max-time 240 "$url" -o "$tmp/$alpine"
echo "$digest  $tmp/$alpine" | sha256sum -c -
cargo build --manifest-path agent/Cargo.toml --locked --release --bin bootnexa-media
agent/target/release/bootnexa-media build-alpine-virtual "$tmp/$alpine" "$tmp" > "$tmp/report.json"
python3 - "$tmp" "$digest" "$alpine_version" <<'PY'
import hashlib,json,pathlib,sys
d=pathlib.Path(sys.argv[1])
expected=sys.argv[2]
r=json.loads((d/"report.json").read_text())
assert r["virtualOnly"] and not r["physicalWriteAuthorized"]
m=r["media"]
assert m["distroProfile"]==f"alpine-virt-{sys.argv[3]}-x86_64"
assert m["publisherSha256Matched"] and m["mbrEfiPartitionVerified"] and m["fatEfiBootloaderVerified"]
assert not m["bootExecutionVerified"] and not m["linuxDistributionBootVerified"]
assert r["outputSha256"]==expected==hashlib.file_digest(open(r["outputPath"],"rb"),"sha256").hexdigest()
PY
image="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["outputPath"])' "$tmp/report.json")"
code=""
vars=""
for dir in /usr/share/OVMF /usr/share/ovmf; do
  for f in "$dir/OVMF_CODE_4M.fd" "$dir/OVMF_CODE.fd"; do
    if [[ -f "$f" ]]; then code="$f"; break; fi
  done
  for f in "$dir/OVMF_VARS_4M.fd" "$dir/OVMF_VARS.fd"; do
    if [[ -f "$f" ]]; then vars="$f"; break; fi
  done
  if [[ -n "$code" && -n "$vars" ]]; then break;fi
done
if [[ -z "$code" || -z "$vars" ]]; then echo "OVMF firmware missing";exit 1;fi
cp "$vars" "$tmp/VARS.fd"
# QEMU uses a transient COW layer. The verified ISO and .img are read-only
# test inputs and cannot be modified through this emulated disk.
qemu-system-x86_64 \
  -machine q35 -accel tcg -m 1024 \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,unit=1,file=$tmp/VARS.fd" \
  -drive "id=media,if=none,format=raw,snapshot=on,file=$image" \
  -device ich9-ahci,id=ahci \
  -device ide-hd,drive=media,bus=ahci.0 \
  -display none -monitor none -net none -no-reboot \
  -serial "file:$tmp/alpine-serial.log" \
  -debugcon "file:$tmp/ovmf-debug.log" -global isa-debugcon.iobase=0xe9 \
  > "$tmp/qemu.log" 2>&1 &
qemu_pid="$!"
booted=0
for i in $(seq 1 90); do
  if [[ -f "$tmp/alpine-serial.log" ]] &&
    grep -aEiq '(alpine|localhost)[[:space:]]+login:' "$tmp/alpine-serial.log"; then
    booted=1; break
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    echo "QEMU stopped before Linux login prompt";break
  fi
  sleep 2
done
if [[ "$booted" -ne 1 ]];then
  echo "Alpine OS boot NOT verified: serial login prompt absent."
  echo "serial tail:"; tail -c 8000 "$tmp/alpine-serial.log" 2>/dev/null || true
  echo "qemu tail:"; tail -c 2500 "$tmp/qemu.log" || true
  exit 1
fi
# Freeze the serial transcript before its SHA-256 is recorded in the receipt.
kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=''
python3 tests/virtual-media/alpine_boot_evidence.py \
  --report "$tmp/report.json" --serial "$tmp/alpine-serial.log" \
  --firmware "$code" --evidence-dir "$evidence_dir" \
  --revision "$(git rev-parse HEAD)" \
  --profile "alpine-virt-${alpine_version}-x86_64"
echo "PASS: official SHA-pinned Alpine Linux $alpine_version virtual ISO copied byte-for-byte and booted to serial login prompt in QEMU/OVMF."
