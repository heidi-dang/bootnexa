#!/usr/bin/env python3
"""End-to-end JSON plan contract with *synthetic assertions*, no Windows bytes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from test_windows_installer_layout_plan import fixture

CLI=Path("tests/virtual-media/windows_installer_layout_plan.py").resolve()
with tempfile.TemporaryDirectory(prefix="bootnexa-windows-layout-") as folder:
    root=Path(folder)
    src=root/"synthetic-manifest.json"
    src.write_text(json.dumps(fixture(5*1024**3),sort_keys=True))
    expected=hashlib.sha256(src.read_bytes()).hexdigest()
    before={x.name for x in root.iterdir()}
    for gib in (1,8,24):
        run=subprocess.run([sys.executable,str(CLI),"--manifest",str(src),
                            "--disk-gib",str(gib)],
                           capture_output=True,text=True,timeout=15)
        assert run.returncode==0,(run.stdout,run.stderr)
        report=json.loads(run.stdout)
        assert report["schema"]=="bootnexa-windows-installer-layout-plan-v1"
        assert report["inputManifestSha256"]==expected
        assert report["inputFileCount"]==6
        assert report["requiresSplitWim"]
        assert report["installationPayloadKind"]=="WIM"
        assert report["proposedWimlibSplitTargetBytes"]==3800*1024**2
        assert report["estimatedSplitPartsNotGuaranteed"]>=2
        assert not report["actualSplitWimArtifactsVerified"]
        assert not report["splitWimFilesGenerated"]
        assert not report["virtualDiskGenerated"]
        assert not report["manifestAssertionsTrusted"]
        assert not report["actionable"]
        assert not report["windowsSetupBootVerified"]
        assert not report["physicalWriteAuthorized"]
        partitions=report["proposedPartitionLayout"]
        assert partitions["efi"]["bytes"]==256*1024**2
        assert partitions["payload"]["firstLba"]==partitions["efi"]["lastLba"]+1
        assert partitions["payload"]["lastLba"]==(gib*1024**3//512)-34
        assert all(len(x["sha256"])==64 for x in report["filePlacements"])
        assert any(p.get("stageAction")=="replace_with_verified_swm"
                   for p in report["filePlacements"])
        if gib==1:
            assert "fat32_payload_partition_capacity_exceeded" in report["blockers"]
        print(f"PASS synthetic {gib} GiB GPT/FAT32 WIM-split layout report and all refusal flags")
    for gib in (0,25,-1):
        run=subprocess.run([sys.executable,str(CLI),"--manifest",str(src),
                            "--disk-gib",str(gib)],capture_output=True,text=True)
        assert run.returncode!=0 and not run.stdout.strip()
    bad=root/"tampered.json"
    doc=fixture()
    doc["publisherChecksumReference"]["referenceSha256"]="9"*64
    bad.write_text(json.dumps(doc))
    rejected=subprocess.run([sys.executable,str(CLI),"--manifest",str(bad),
                             "--disk-gib","8"],capture_output=True,text=True)
    assert rejected.returncode!=0
    assert not rejected.stdout.strip()
    assert {x.name for x in root.iterdir()}==before|{"tampered.json"}
    print("PASS wrong publisher-bound digest and disk capacities rejected without writing a disk")

print("PASS manifest-derived planning only; no ISO extraction, real WIM split or physical media authority")
