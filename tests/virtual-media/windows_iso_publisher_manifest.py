#!/usr/bin/env python3
"""Read-only, evidence-gated Windows 11 ISO intake and complete file manifest.

Microsoft checksum values are fetched from the *fixed* Microsoft Australia
HTTPS download page. The operator cannot supply a self-authenticating hash.
Every real ISO file is read and SHA-256 checked through 7-Zip -so; nothing is
extracted to host paths. Virtual [BOOT] objects are deliberately not files.
This does not establish Windows Setup boot or image writability.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse

OFFICIAL_URL="https://www.microsoft.com/en-au/software-download/windows11"
MAX_PAGE=1_048_576
MAX_ISO=24*1024**3
MIN_OFFICIAL_ISO=512*1024**2
MAX_LISTING=12*1024**2
MAX_FILES=4096
MAX_PATH=240
MAX_FILE=16*1024**3
MAX_SUM=24*1024**3
MAX_EXTRACT_SECONDS=1800
MAX_TOTAL_SECONDS=7200
BUFSIZE=65536
SUPPORTED_LOCALES=("English International 64-bit", "English 64-bit")
MANDATORY_WINDOWS_FILES=frozenset((
    "EFI/BOOT/BOOTX64.EFI","SOURCES/BOOT.WIM","SETUP.EXE"
))
EXCLUDED_BOOT_PREFIX="[BOOT]/"

class Rejected(ValueError):
    pass

def safe_regular(path):
    p=Path(path)
    st=p.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise Rejected("ISO must be a regular file; symlinks and devices are forbidden")
    return p.resolve()

def safe_parent(path):
    p=Path(path)
    if not stat.S_ISDIR(p.lstat().st_mode):
        raise Rejected("evidence destination must be an existing real directory")
    return p.resolve()

def file_sha(path, maximum):
    p=safe_regular(path)
    length=p.stat().st_size
    if length<=0 or length>maximum:
        raise Rejected("ISO length exceeds bounded policy or is empty")
    result=hashlib.sha256()
    count=0
    with p.open("rb") as file:
        while chunk:=file.read(256*1024):
            count+=len(chunk)
            if count>maximum:
                raise Rejected("ISO grew while hashing")
            result.update(chunk)
    if count!=length or p.stat().st_size!=length:
        raise Rejected("ISO size changed during hashing")
    return count,result.hexdigest()

class DigestTable(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth=0
        self.rows=[]
        self.row=None
        self.cell=None
    def handle_starttag(self, tag, attrs):
        if tag=="tr":
            self.row=[]
        if tag=="td" and self.row is not None:
            self.cell=[]
    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)
    def handle_endtag(self, tag):
        if tag=="td" and self.cell is not None:
            self.row.append(" ".join("".join(self.cell).split()))
            self.cell=None
        if tag=="tr" and self.row is not None:
            self.rows.append(self.row)
            self.row=None

class MicrosoftOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p=urllib.parse.urlsplit(newurl)
        if p.scheme!="https" or p.hostname!="www.microsoft.com" or p.port is not None:
            raise Rejected("publisher URL redirected outside the pinned HTTPS origin")
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def parse_official_html(blob, locale):
    if locale not in SUPPORTED_LOCALES:
        raise Rejected("unsupported or ambiguous Microsoft ISO locale")
    page=DigestTable()
    try:
        page.feed(blob.decode("utf-8","strict"))
    except UnicodeDecodeError as e:
        raise Rejected("invalid publisher page encoding") from e
    matches=[row[1].upper() for row in page.rows
             if len(row)==2 and row[0]==locale]
    if len(matches)!=1 or not re.fullmatch(r"[0-9A-F]{64}",matches[0]):
        raise Rejected("expected unique locale/hash row unavailable on Microsoft page")
    return matches[0].lower()

def fetch_publisher_reference(locale):
    if locale not in SUPPORTED_LOCALES:
        raise Rejected("locale must identify an exact supported x64 image")
    # Host pinned in both URL and redirect policy; TLS defaults to Python's
    # certificate-validation policy. No operator-controlled URLs or proxies.
    opener=urllib.request.build_opener(MicrosoftOnlyRedirect())
    request=urllib.request.Request(OFFICIAL_URL,headers={
        "User-Agent":"BootnexaIsoVerifier/0.1 (read-only HTTPS validation)",
        "Accept":"text/html",
    })
    try:
        with opener.open(request,timeout=20) as response:
            if response.status!=200:
                raise Rejected("Microsoft publisher checksum endpoint unavailable")
            payload=response.read(MAX_PAGE+1)
            if len(payload)>MAX_PAGE:
                raise Rejected("publisher checksum page exceeds bounded size")
    except (OSError,ValueError) as e:
        raise Rejected("Microsoft SHA256 verification unavailable; fail closed") from e
    return {
        "sourceUrl":OFFICIAL_URL,
        "sourceSha256":hashlib.sha256(payload).hexdigest(),
        "fetchedUtc":datetime.now(timezone.utc).isoformat(),
        "locale":locale,
        "referenceSha256":parse_official_html(payload,locale),
        "issuer":"Microsoft public download-page HTTPS response",
        "releaseBuildIndependentlyVerified":False,
    }

def checked_path(value):
    if not isinstance(value,str) or not value or len(value.encode("utf-8"))>MAX_PATH:
        raise Rejected("archive path missing or exceeds 240-byte budget")
    if value.startswith(("/","\\")) or "\\" in value or ":" in value:
        raise Rejected("absolute, Windows, or escaped ISO path forbidden")
    segments=value.split("/")
    if len(segments)>16 or any(not s or s in (".","..") or s.startswith("-")
                               for s in segments):
        raise Rejected("ambiguous ISO path or traversal")
    # Reject names with globs, control characters and 7-Zip subcommand markup.
    if any(ord(ch)<32 or ch in "*?<>|\"\x7f" for ch in value):
        raise Rejected("ISO file path requires unsupported escaping")
    return value

def sevenzip_executable():
    name=shutil.which("7z")
    if not name:
        raise Rejected("7z not installed; trusted 7zip package required")
    p=safe_regular(name)
    return str(p)

def parse_listing(raw, iso, length):
    text=raw.decode("utf-8","strict")
    if "\n----------\n" not in text.replace("\r\n","\n"):
        raise Rejected("7-Zip listing separator or ISO tree missing")
    header,listing=text.replace("\r\n","\n").split("\n----------\n",1)
    if not re.search(r"(?m)^Type = (Iso|Udf)$",header):
        raise Rejected("archive decoder did not identify optical media")
    size=re.search(r"(?m)^Physical Size = (\d+)$",header)
    if not size or int(size.group(1))!=length:
        raise Rejected("7-Zip observed image length disagrees with hashed ISO")
    entries=[]
    seen=set()
    skipped=[]
    total=0
    for segment in listing.strip().split("\n\n"):
        lines={}
        for row in segment.splitlines():
            if " = " in row:
                k,v=row.split(" = ",1)
                if k in lines:
                    raise Rejected("duplicate archive metadata property")
                lines[k]=v
        if not lines:
            continue
        raw_path=lines.get("Path")
        if raw_path is None:
            raise Rejected("archive entry missing path")
        if raw_path.startswith(EXCLUDED_BOOT_PREFIX):
            # 7z synthesizes the El Torito [BOOT] view; not an ISO/UDF file.
            if lines.get("Folder")!="-" or not re.fullmatch(r"\d+",lines.get("Size","")):
                raise Rejected("malformed virtual boot-track entry")
            skipped.append(raw_path)
            continue
        path=checked_path(raw_path)
        folded=path.casefold()
        if folded in seen:
            raise Rejected("duplicate or case-conflicting ISO namespace entry")
        seen.add(folded)
        if lines.get("Symbolic Link","") or lines.get("Hard Link",""):
            raise Rejected("ISO links not supported for full manifest")
        if lines.get("Folder")=="+":continue
        if lines.get("Folder")!="-" or not re.fullmatch(r"\d+",lines.get("Size","")):
            raise Rejected("unsupported ISO entry metadata")
        size=int(lines["Size"])
        if size>MAX_FILE:
            raise Rejected("single extracted ISO file exceeds 16 GiB bound")
        total+=size
        if total>MAX_SUM:
            raise Rejected("total ISO file content exceeds 24 GiB bound")
        entries.append({"path":path,"bytes":size})
        if len(entries)>MAX_FILES:
            raise Rejected("ISO namespace exceeds 4096 files")
    if not entries:
        raise Rejected("empty ISO namespace")
    return entries,skipped

def listing(iso,exe,size):
    # Bound pipe capture *while reading*, not after unbounded communicate().
    proc=subprocess.Popen(
        [exe,"l","-slt","-bd","-spd",str(iso)],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector()
    selector.register(proc.stdout,selectors.EVENT_READ)
    selector.register(proc.stderr,selectors.EVENT_READ)
    chunks=[]
    stdout_bytes=0
    stderr_bytes=0
    started=time.monotonic()
    try:
        while selector.get_map():
            if time.monotonic()-started>180:
                raise Rejected("ISO inventory exceeded listing timeout")
            for key,_ in selector.select(timeout=1):
                data=os.read(key.fileobj.fileno(),BUFSIZE)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is proc.stdout:
                    stdout_bytes+=len(data)
                    if stdout_bytes>MAX_LISTING:
                        raise Rejected("ISO inventory exceeds bounded memory budget")
                    chunks.append(data)
                else:
                    stderr_bytes+=len(data)
                    if stderr_bytes>65536:
                        raise Rejected("ISO inventory stderr exceeds bounded memory budget")
        if proc.wait(timeout=3)!=0:
            raise Rejected("ISO inventory decoder rejected optical image")
    except (OSError,subprocess.TimeoutExpired) as e:
        raise Rejected("ISO inventory tool failed or stalled") from e
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    return parse_listing(b"".join(chunks),iso,size)

def streamed_entry_sha(exe,iso,name,expected,deadline):
    start=time.monotonic()
    cmd=[exe,"x","-so","-bd","-spd",str(iso),name]
    proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    counter=0
    stderr_size=0
    sha=hashlib.sha256()
    selector=selectors.DefaultSelector()
    selector.register(proc.stdout,selectors.EVENT_READ)
    selector.register(proc.stderr,selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining=min(MAX_EXTRACT_SECONDS-(time.monotonic()-start),
                          deadline-time.monotonic())
            if remaining<=0:
                raise Rejected("ISO streaming exceeded time budget")
            events=selector.select(timeout=min(30,remaining))
            if not events and proc.poll() is not None:
                continue
            for key,_ in events:
                chunk=os.read(key.fileobj.fileno(),BUFSIZE)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is proc.stdout:
                    counter+=len(chunk)
                    if counter>expected:
                        raise Rejected("extracted ISO bytes exceed advertised length")
                    sha.update(chunk)
                else:
                    stderr_size+=len(chunk)
                    if stderr_size>65536:
                        raise Rejected("ISO decoder stderr budget exceeded")
        if proc.wait(timeout=3)!=0:
            raise Rejected("ISO decoder failed while reading a named entry")
    except (OSError,subprocess.TimeoutExpired) as e:
        raise Rejected("ISO file streaming failed") from e
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    if counter!=expected:
        raise Rejected("extracted ISO byte count differs from listing")
    return sha.hexdigest()

def build_manifest(iso,official_reference,*,minimum=MIN_OFFICIAL_ISO,
                   require_windows=True,exe=None):
    iso=safe_regular(iso)
    size,source_sha=file_sha(iso,MAX_ISO)
    if size<minimum:
        raise Rejected("ISO smaller than accepted official-media minimum")
    if source_sha != official_reference["referenceSha256"]:
        raise Rejected("ISO SHA256 does not match current independently fetched Microsoft reference")
    decoder=exe or sevenzip_executable()
    entries,virtual=listing(iso,decoder,size)
    upper={entry["path"].upper() for entry in entries}
    if require_windows and (not MANDATORY_WINDOWS_FILES.issubset(upper)
        or not ({"SOURCES/INSTALL.WIM","SOURCES/INSTALL.ESD"} & upper)):
        raise Rejected("ISO lacks required Windows Setup/EFI/WIM file names")
    deadline=time.monotonic()+MAX_TOTAL_SECONDS
    for entry in entries:
        entry["sha256"]=streamed_entry_sha(
            decoder,iso,entry["path"],entry["bytes"],deadline)
    after_size,after_sha=file_sha(iso,MAX_ISO)
    if (after_size,after_sha)!=(size,source_sha):
        raise Rejected("ISO changed during complete file-manifest hash")
    return {
        "schema":"bootnexa-official-iso-manifest-v1",
        "createdUtc":datetime.now(timezone.utc).isoformat(),
        "sourceBytes":size,
        "sourceSha256":source_sha,
        "isoSourceUnchanged":True,
        "publisherChecksumMatched":True,
        "publisherChecksumReference":official_reference,
        "allListedFilesIndependentlyHashed":True,
        "listedFileCount":len(entries),
        "virtualElToritoViewsExcluded":len(virtual),
        "files":entries,
        "windowsSetupBootVerified":False,
        "physicalWriteAuthorized":False,
        "installerCompatibleVerified":False,
        "fullSizeWindowsUsbProduced":False,
        "manualSetupReviewRequired":True,
        "hasRequiredWindowsFileNames":MANDATORY_WINDOWS_FILES.issubset(upper),
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iso",type=Path,required=True)
    ap.add_argument("--locale",required=True,choices=SUPPORTED_LOCALES)
    ap.add_argument("--evidence-parent",required=True,type=Path)
    args=ap.parse_args()
    try:
        parent=safe_parent(args.evidence_parent)
        official=fetch_publisher_reference(args.locale)
        # Do not create evidence directory before complete independent proof.
        result=build_manifest(args.iso,official)
        temp=Path(tempfile.mkdtemp(prefix="bootnexa-iso-manifest-",dir=parent))
        temp.chmod(0o700)
        dest=temp/"manifest.json"
        dest.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        result["evidenceDirectory"]=str(temp)
    except (Rejected,ValueError,OSError,subprocess.SubprocessError) as e:
        print("DENIED: "+str(e),file=sys.stderr)
        return 1
    print(json.dumps({k:v for k,v in result.items() if k!="files"},indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
