#!/usr/bin/env python3
"""MIT synthetic ISO9660 primary-tree fixture. No proprietary OS binaries."""
import argparse
from pathlib import Path
import math
import struct

P = argparse.ArgumentParser()
P.add_argument("efi", type=Path)
P.add_argument("output", type=Path)
P.add_argument("--profile", choices=("efi", "windows", "linux"), default="efi")
args = P.parse_args()

efi = args.efi.read_bytes()
assert 256 <= len(efi) <= 8*1024*1024
sectors = 64 + math.ceil(len(efi)/2048) + 4
assert sectors <= 4096
image = bytearray(sectors*2048)

def dual32(value):
    return struct.pack("<I",value)+struct.pack(">I",value)

def record(lba,size,name,dir=False):
    assert len(name)<100
    rec = bytearray(33+len(name)+(len(name)%2==0))
    rec[0]=len(rec)
    rec[2:10]=dual32(lba)
    rec[10:18]=dual32(size)
    rec[25]=2 if dir else 0
    rec[28:30]=struct.pack("<H",1)
    rec[30:32]=struct.pack(">H",1)
    rec[32]=len(name)
    rec[33:33+len(name)]=name
    return rec

def put_sector(lba, data):
    assert len(data)<=2048
    image[lba*2048:lba*2048+len(data)]=data

def directory(lba,entries):
    out=bytearray(2048)
    offset=0
    for entry in entries:
        if offset+len(entry)>2048:raise ValueError("directory too large")
        out[offset:offset+len(entry)]=entry
        offset+=len(entry)
    put_sector(lba,out)

pvd=16*2048
image[pvd]=1;image[pvd+1:pvd+6]=b"CD001";image[pvd+6]=1
image[pvd+40:pvd+72]=b"BOOTNEXA VIRTUAL".ljust(32,b" ")
image[pvd+80:pvd+88]=dual32(sectors)
image[pvd+128:pvd+130]=struct.pack("<H",2048)
image[pvd+130:pvd+132]=struct.pack(">H",2048)
root=record(22,2048,b"\x00",True)
image[pvd+156:pvd+156+len(root)]=root
boot=17*2048
image[boot]=0;image[boot+1:boot+6]=b"CD001";image[boot+6]=1
image[boot+7:boot+30]=b"EL TORITO SPECIFICATION"
image[boot+71:boot+75]=struct.pack("<I",40)
term=18*2048
image[term]=255;image[term+1:term+6]=b"CD001";image[term+6]=1
catalog=bytearray(2048)
catalog[0]=1;catalog[1]=0xef;catalog[30]=0x55;catalog[31]=0xaa
checksum=sum(struct.unpack("<16H",catalog[:32]))%65536
catalog[28:30]=struct.pack("<H",(-checksum)%65536)
catalog[32]=0x88
put_sector(40,catalog)
put_sector(60,b"MIT smoke fixture (no OS installation binaries)\n")
image[64*2048:64*2048+len(efi)]=efi
root_entries=[
    record(22,2048,b"\x00",True),
    record(22,2048,b"\x01",True),
    record(23,2048,b"EFI",True),
    record(60,46,b"README.TXT;1")]
directory(23,[record(23,2048,b"\x00",True),
    record(22,2048,b"\x01",True),
    record(24,2048,b"BOOT",True)])
directory(24,[record(24,2048,b"\x00",True),
    record(23,2048,b"\x01",True),
    record(64,len(efi),b"BOOTX64.EFI;1")])
if args.profile != "efi":
    folder = b"SOURCES" if args.profile=="windows" else b"CASPER"
    name=b"BOOT.WIM;1" if args.profile=="windows" else b"VMLINUZ;1"
    root_entries.append(record(26,2048,folder,True))
    directory(26,[record(26,2048,b"\x00",True),
        record(22,2048,b"\x01",True),
        record(61,16,name)])
    put_sector(61,b"INCOMPLETE-TEST!!")
directory(22,root_entries)
args.output.write_bytes(image)
print(f"Synthetic valid ISO9660 test fixture: {args.output} ({len(image)} bytes); profile={args.profile}")
