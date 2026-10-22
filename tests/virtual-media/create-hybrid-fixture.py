#!/usr/bin/env python3
"""Synthetic ISO9660 + GPT + FAT32 ESP dual-format boot fixture.

Only modifies a developer-produced regular-file virtual GPT image, never an
OS drive/device. Not an example of a general-purpose Linux hybrid ISO.
"""
import argparse
import math
import struct
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument("base",type=Path)
parser.add_argument("efi",type=Path)
parser.add_argument("output",type=Path)
args=parser.parse_args()
assert args.base.is_file() and args.efi.is_file()
assert args.base.stat().st_size == 96*1024*1024
app=args.efi.read_bytes()
assert 256<=len(app)<=128*1024
assert args.base.resolve()!=args.output.resolve()
assert args.output!=args.efi

def dual(v):
    return struct.pack("<I",v)+struct.pack(">I",v)
def rec(lba,size,name,is_dir=False):
    length=33+len(name)+(len(name)%2==0)
    assert length<=255
    b=bytearray(length)
    b[0]=length;b[2:10]=dual(lba);b[10:18]=dual(size)
    b[25]=2 if is_dir else 0
    b[28:30]=struct.pack("<H",1);b[30:32]=struct.pack(">H",1)
    b[32]=len(name);b[33:33+len(name)]=name
    return bytes(b)
def put(f,lba,content):
    assert len(content)<=2048
    f.seek(lba*2048)
    f.write(content)
def directory(f,lba,entries):
    buf=bytearray(2048)
    pos=0
    for item in entries:
        assert pos+len(item)<=2048
        buf[pos:pos+len(item)]=item
        pos+=len(item)
    put(f,lba,buf)

import shutil
with args.base.open("rb") as original, args.output.open("xb") as dst:
    shutil.copyfileobj(original,dst,length=64*1024)

with args.output.open("r+b") as f:
    size=args.output.stat().st_size
    block_count=size//2048
    pvd=bytearray(2048)
    pvd[0]=1;pvd[1:6]=b"CD001";pvd[6]=1
    pvd[40:72]=b"BOOTNEXA SYNTHETIC HYBRID".ljust(32,b" ")
    pvd[80:88]=dual(block_count)
    pvd[128:130]=struct.pack("<H",2048);pvd[130:132]=struct.pack(">H",2048)
    root=rec(22,2048,b"\0",True)
    pvd[156:156+len(root)]=root
    put(f,16,pvd)
    desc=bytearray(2048)
    desc[0]=0;desc[1:6]=b"CD001";desc[6]=1
    desc[7:30]=b"EL TORITO SPECIFICATION"
    desc[71:75]=struct.pack("<I",40)
    put(f,17,desc)
    end=bytearray(2048)
    end[0]=255;end[1:6]=b"CD001";end[6]=1
    put(f,18,end)
    catalog=bytearray(2048)
    catalog[0]=1;catalog[1]=0xef
    catalog[30]=0x55;catalog[31]=0xaa
    words=struct.unpack("<16H",catalog[:32])
    catalog[28:30]=struct.pack("<H",(-sum(words))&0xffff)
    catalog[32]=0x88
    catalog[32+8:32+12]=struct.pack("<I",512)
    put(f,40,catalog)
    directory(f,22,[
        rec(22,2048,b"\0",True),rec(22,2048,b"\1",True),
        rec(23,2048,b"EFI",True),rec(70,23,b"README.TXT;1")])
    directory(f,23,[
        rec(23,2048,b"\0",True),rec(22,2048,b"\1",True),
        rec(24,2048,b"BOOT",True)])
    directory(f,24,[
        rec(24,2048,b"\0",True),rec(23,2048,b"\1",True),
        rec(64,len(app),b"BOOTX64.EFI;1")])
    for offset in range(0,len(app),2048):
        put(f,64+offset//2048,app[offset:offset+2048])
    put(f,70,b"BootNexa synthetic test\n")
    f.flush()
print(f"Dual-format synthetic ISO9660/GPT/FAT32 image: {args.output} ({size} bytes)")
