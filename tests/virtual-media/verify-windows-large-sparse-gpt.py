#!/usr/bin/env python3
"""Phase 8 large sparse GPT/EFI capacity qualification, no exported disk."""
import json
import re
import subprocess
from pathlib import Path

CLI=Path("agent/target/debug/bootnexa-media")
assert CLI.is_file(),"build bootnexa-media before large-capacity proof"

def run(capacity):
    return subprocess.run([str(CLI),"qualify-large-windows-gpt",str(capacity)],
                          capture_output=True,text=True,timeout=90)

for gib in (1,8,24):
    process=run(gib)
    assert process.returncode==0,(gib,process.stderr)
    receipt=json.loads(process.stdout)
    assert receipt["virtualOnly"] is True
    assert receipt["physicalWriteAuthorized"] is False
    assert receipt["windowsSetupBootVerified"] is False
    assert receipt["windowsInstallerCompatible"] is False
    assert receipt["bootExecutionVerified"] is False
    assert receipt["payloadFilesystemFormatted"] is False
    assert receipt["ntfsWriterAvailable"] is False
    assert receipt["fullDiskSha256Verified"] is False
    assert receipt["primaryAndBackupGptVerified"] is True
    assert receipt["espFat32Verified"] is True
    assert receipt["reservedPayloadSampledZero"] is True
    assert receipt["diskBytes"]==gib*1024**3
    assert receipt["espBytes"]==256*1024**2
    assert receipt["espFirstLba"]==2048
    assert receipt["espLastLba"]+1==receipt["reservedPayloadFirstLba"]
    assert receipt["reservedPayloadLastLba"]>receipt["reservedPayloadFirstLba"]
    assert receipt["reservedPayloadBytes"]>512*1024**2
    assert re.fullmatch(r"[0-9a-f]{64}",receipt["metadataSha256"])
    print(f"PASS {gib} GiB anonymous sparse GPT, FAT32 EFI, unformatted payload, metadata hash and refusal flags")
for invalid in ("0","25","4294967295","-1","garbage"):
    process=run(invalid)
    assert process.returncode!=0 and process.stdout.strip()=="",invalid
    print(f"PASS unsupported capacity {invalid!r} refused")
print("PASS large-capacity virtual layout qualification: no exported disk, NTFS or USB writer")
