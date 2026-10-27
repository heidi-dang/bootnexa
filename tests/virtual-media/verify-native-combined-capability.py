#!/usr/bin/env python3
"""CI-only read-only binary capability qualification, never writes media."""
import json
from pathlib import Path
import subprocess

from windows_genuine_iso_readiness import native_combined_capability

cli=Path("agent/target/debug/bootnexa-media").resolve()
assert cli.is_file()
assert native_combined_capability(cli), "native binary lacks required source-bound combined virtual staging capability"
result=subprocess.run([str(cli),"capabilities"],stdin=subprocess.DEVNULL,
                      capture_output=True,timeout=5,check=True)
receipt=json.loads(result.stdout)
assert receipt["combinedIsoStreamMagic"]=="BNXI0002"
assert receipt["virtualOnly"] is True
assert receipt["physicalWriteAuthorized"] is False
assert receipt["persistentDiskImageProduced"] is False
assert receipt["officialWindowsSetupBootVerified"] is False
print("PASS native compiled binary advertises BNXI0002 anonymous-only combined staging")
print("PASS capability inspection performs no physical-write, disk-image or Setup-boot assertion")
