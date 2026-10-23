#!/usr/bin/env python3
"""Independent synthetic UDF descriptor-chain + Windows layout planner acceptance.

No Windows binaries, data extraction, physical writes, real installer execution.
"""
from pathlib import Path
import binascii
import json
import struct
import subprocess
import sys
import tempfile

CLI=Path(sys.argv[1] if len(sys.argv)>1 else "agent/target/debug/bootnexa-media").resolve()
BLK=2048
def put16(buf, offset, value): struct.pack_into("<H",buf,offset,value)
def put32(buf, offset, value): struct.pack_into("<I",buf,offset,value)
def desc(kind, tagloc, fields=None):
    b=bytearray(BLK)
    put16(b,0,kind)
    put16(b,2,2)
    put32(b,12,tagloc)
    if fields: fields(b)
    put16(b,10,496)
    put16(b,8,binascii.crc_hqx(b[16:512],0))
    b[4]=sum(b[i] for i in range(16) if i!=4)&255
    return b

def source(path):
    with path.open("r+b") as f:
        f.truncate(370*BLK)
        def block(lba, content):
            f.seek(lba*BLK);f.write(content)
        for lba,sig in [(19,b"BEA01"),(20,b"NSR03"),(21,b"TEA01")]:
            block(lba,b"\x00"+sig)
        block(256,desc(2,256,lambda b:(put32(b,16,16*BLK),put32(b,20,32))))
        block(32,desc(1,32))
        block(33,desc(5,33,lambda b:(
            put16(b,22,7),put32(b,188,280),put32(b,192,75))))
        def lvd(b):
            put32(b,212,BLK)
            b[217:236]=b"*OSTA UDF Compliant"
            put32(b,248,BLK);put32(b,252,1);put16(b,256,7)
            put32(b,264,6);put32(b,268,1)
            b[440]=1;b[441]=6;put16(b,442,1);put16(b,444,7)
        block(34,desc(6,34,lvd))
        block(35,desc(8,35))
        block(281,desc(256,1,lambda b:(put32(b,400,BLK),put32(b,404,2),put16(b,408,7))))
        block(282,desc(261,2,lambda b:(b.__setitem__(27,4),put32(b,172,8))))

with tempfile.TemporaryDirectory(prefix="bootnexa-udf-structure-") as tmp:
    root=Path(tmp)
    efi=root/"not-an-os.efi"
    b=bytearray(512)
    b[:2]=b"MZ";put32(b,0x3c,0x80);b[0x80:0x84]=b"PE\x00\x00"
    put16(b,0x84,0x8664);put16(b,0x98,0x20b);put16(b,0x98+68,10)
    efi.write_bytes(b)
    iso=root/"synthetic-windows-udf.iso"
    subprocess.run([sys.executable,"tests/virtual-media/create-iso-fixture.py",str(efi),
                    str(iso),"--profile","windows-preflight"],check=True)
    source(iso)
    def invoke(op,p=iso):
        return subprocess.run([str(CLI),op,str(p)],capture_output=True,text=True)
    d=invoke("inspect-udf-structure")
    assert d.returncode==0,d.stderr
    u=json.loads(d.stdout)
    assert u["descriptorChainVerified"] and u["rootIcbTagVerified"]
    assert u["fileSetDescriptorLba"]==281 and u["rootIcbLba"]==282
    assert not u["fileTreeTraversalSupported"]
    assert not u["physicalWriteAuthorized"] and not u["installerBootVerified"]
    print("PASS ECMA-167 anchor/VDS/LVD/partition/FSD/root ICB structural chain with CRC")

    result=invoke("plan-windows-media")
    assert result.returncode==0,result.stderr
    report=json.loads(result.stdout)
    insp,plan=report["inspection"],report["layoutPlan"]
    assert insp["udfSignatureObserved"] and insp["udfStructuralMetadataVerified"]
    assert insp["udfStructure"]["rootIcbTagVerified"]
    assert not insp["virtualCdromStagingEligible"]
    assert not plan["actionable"] and not plan["physicalWriteAuthorized"]
    assert not plan["virtualUsbBuilderImplemented"] and not plan["splitWimImplemented"]
    assert plan["state"]=="udf_translation_and_file_tree_consistency_required"
    assert invoke("stage-windows-virtual-cdrom").returncode != 0
    print("PASS verified UDF metadata never grants Windows Setup, USB or optical staging")

    for name,lba,offset in [
        ("anchor-checksum",256,4),("anchor-extent",256,20),
        ("logical-volume-crc",34,219),("file-set-root",281,404),
        ("root-file-entry",282,27)]:
        bad=root/(name+".iso")
        bad.write_bytes(iso.read_bytes())
        with bad.open("r+b") as f:
            f.seek(lba*BLK+offset)
            first=f.read(1);f.seek(lba*BLK+offset);f.write(bytes([first[0]^0x80]))
        assert invoke("inspect-udf-structure",bad).returncode != 0,name
        assert invoke("stage-windows-virtual-cdrom",bad).returncode != 0,name
        print("PASS rejects tampered "+name)

    short=root/"truncated.iso"
    short.write_bytes(iso.read_bytes()[:255*BLK])
    assert invoke("inspect-udf-structure",short).returncode != 0
    print("PASS refuses truncated anchor and does not claim success")
print("PASS synthetic UDF structure / Windows media-plan integration")
