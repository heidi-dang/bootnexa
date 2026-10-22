#!/usr/bin/env bash
set -euo pipefail
# Called by boot-ovmf.sh after Rust EFI fixture and release media CLI exist.
tmp="$1"
code="$2"
vars="$3"
agent/target/release/bootnexa-media build-virtual "$tmp/BOOTX64.EFI" "$tmp" gpt > "$tmp/hybrid-base.json"
python3 - "$tmp" <<'PY'
import json,subprocess,sys,pathlib
d=pathlib.Path(sys.argv[1])
base=json.loads((d/"hybrid-base.json").read_text())
subprocess.check_call(["python3","tests/virtual-media/create-hybrid-fixture.py",
                       base["outputPath"],str(d/"BOOTX64.EFI"),str(d/"hybrid.iso")])
PY
agent/target/release/bootnexa-media build-hybrid-virtual "$tmp/hybrid.iso" "$tmp" > "$tmp/hybrid-report.json"
python3 - "$tmp" <<'PY'
import json,hashlib,pathlib,sys
d=pathlib.Path(sys.argv[1])
r=json.loads((d/"hybrid-report.json").read_text())
assert r["virtualOnly"] and not r["physicalWriteAuthorized"]
m=r["media"]
assert m["iso9660Verified"] and m["gptPrimaryBackupVerified"] and m["fat32EfiVerified"] and m["isoEspEfiMatch"]
assert not m["bootExecutionVerified"] and not m["linuxDistributionBootVerified"] and not m["windowsSetupVerified"]
assert m["sourceSha256"]==r["outputSha256"]==hashlib.file_digest(open(d/"hybrid.iso","rb"),"sha256").hexdigest()
assert pathlib.Path(r["outputPath"]).stat().st_size == 96*1024*1024
# Every invalid hybrid mutation must fail closed BEFORE a virtual .img is
# marked qualified. Only synthetic fixtures are modified, never user media.
for label,offset in (("gpt",512+15),("catalog",40*2048+30),("iso-efi",64*2048+250),("fat-efi",1024*1024+510)):
    bad=d/(f"invalid-{label}.iso")
    import shutil
    shutil.copyfile(d/"hybrid.iso",bad)
    with bad.open("r+b") as f:
        f.seek(offset)
        original=f.read(1)
        f.seek(offset)
        f.write(bytes([original[0]^0xFF]))
    import subprocess
    result=subprocess.run(["agent/target/release/bootnexa-media","build-hybrid-virtual",
                           str(bad),str(d)],capture_output=True,text=True)
    if result.returncode==0:
        raise AssertionError("Corrupt hybrid incorrectly accepted: "+label)
    print("PASS: hybrid mismatch rejected:",label)
PY
image="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["outputPath"])' "$tmp/hybrid-report.json")"
cp "$vars" "$tmp/HYBRID-VARS.fd"
status=0
timeout 55s qemu-system-x86_64 \
  -machine q35 -accel tcg -m 256 \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,unit=1,file=$tmp/HYBRID-VARS.fd" \
  -drive "id=media,if=none,format=raw,snapshot=on,file=$image" \
  -device ich9-ahci,id=ahci \
  -device ide-hd,drive=media,bus=ahci.0 \
  -debugcon "file:$tmp/hybrid-uefi-debug.log" -global isa-debugcon.iobase=0xe9 \
  -display none -monitor none -serial none -no-reboot -net none > "$tmp/hybrid-qemu.log" 2>&1 || status=$?
if [[ "$status" != 0 && "$status" != 124 ]];then
  cat "$tmp/hybrid-qemu.log"
  echo "Hybrid QEMU stopped unexpectedly, exit $status"
  exit 1
fi
if ! grep -aFq 'BOOTNEXA_UEFI_BOOT_OK' "$tmp/hybrid-uefi-debug.log";then
  cat "$tmp/hybrid-qemu.log"
  echo "Hybrid ISO/GPT/FAT32 output did not boot under OVMF"
  exit 1
fi
echo "PASS: synthetic ISO9660/GPT/FAT32 hybrid copied byte-for-byte and booted via QEMU/OVMF."
