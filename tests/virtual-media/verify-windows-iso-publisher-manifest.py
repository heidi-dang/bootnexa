#!/usr/bin/env python3
"""Synthetic ISO/UDF reader acceptance, with mock publisher SHA.

The production CLI *always* fetches the live Microsoft checksum and enforces
a >=512 MiB ISO. This fixture tests stream/hash machinery only, and carries
no publisher or Windows Setup claims.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

module=Path(__file__).with_name("windows_iso_publisher_manifest.py")
spec=importlib.util.spec_from_file_location("bootnexa_manifest",module)
manifest=importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)

with tempfile.TemporaryDirectory(prefix="bootnexa-official-intake-test-") as tmp:
    root=Path(tmp)
    efi=root/"test-efi"
    pe=bytearray(512)
    pe[:2]=b"MZ";pe[0x3c:0x40]=(0x80).to_bytes(4,"little")
    pe[0x80:0x84]=b"PE\x00\x00"
    pe[0x84:0x86]=bytes([0x64,0x86])
    pe[0x98:0x9a]=bytes([0x0b,0x02])
    pe[0xdc:0xde]=(10).to_bytes(2,"little")
    efi.write_bytes(pe)
    iso=root/"synthetic-windows.iso"
    make=Path("tests/virtual-media/create-iso-fixture.py")
    subprocess.run([sys.executable,str(make),str(efi),str(iso),
                    "--profile","windows-preflight"],check=True)
    reference=hashlib.sha256(iso.read_bytes()).hexdigest()
    stub={
        "locale":"fixture only; NOT a Microsoft reference",
        "referenceSha256":reference,
        "issuer":"synthetic test helper; NOT publisher verification",
        "releaseBuildIndependentlyVerified":False,
    }
    result=manifest.build_manifest(iso,stub,minimum=1,
                                   require_windows=True)
    names={f["path"].upper() for f in result["files"]}
    assert manifest.MANDATORY_WINDOWS_FILES.issubset(names),names
    assert names & {"SOURCES/INSTALL.WIM","SOURCES/INSTALL.ESD"}
    assert result["isoSourceUnchanged"]
    assert result["allListedFilesIndependentlyHashed"]
    assert result["listedFileCount"]>=5
    assert not result["windowsSetupBootVerified"]
    assert not result["physicalWriteAuthorized"]
    assert not result["installerCompatibleVerified"]
    assert not result["fullSizeWindowsUsbProduced"]
    assert result["virtualElToritoViewsExcluded"]>=1
    assert hashlib.sha256(iso.read_bytes()).hexdigest()==reference
    print(f"PASS synthetic Windows-shaped ISO: independently SHA256 scanned {result['listedFileCount']} complete real files via 7z -so")
    print("PASS ISO source unchanged, virtual El Torito [BOOT] excluded from actual filesystem manifest")
    with (root/"test-manifest.json").open("w") as output:
        json.dump(result,output,indent=2)
    with (root/"test-manifest.json").open() as source:
        persisted=json.load(source)
    assert persisted["files"]==result["files"]
    assert all(len(entry["sha256"])==64 for entry in persisted["files"])
    print("PASS full per-file SHA manifest serializes independently and remains non-authoritative")

    wrong=dict(stub,referenceSha256="0"*64)
    try:
        manifest.build_manifest(iso,wrong,minimum=1)
    except manifest.Rejected:
        pass
    else:
        raise AssertionError("incorrect publisher SHA must fail before file reads")
    with iso.open("r+b") as source:
        source.seek(26*2048)
        source.write(b"CORRUPTION!")
    try:
        manifest.build_manifest(iso,stub,minimum=1)
    except manifest.Rejected:
        pass
    else:
        raise AssertionError("mutated ISO must fail before file reads")
    print("PASS wrong reference or tampered source refuses full-file scan")

print("PASS only synthetic format tests, no official Windows Setup attestation")
