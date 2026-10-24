#!/usr/bin/env python3
"""Evidence-only, read-only QEMU/OVMF acceptance for an operator-supplied ISO.

No Microsoft media is bundled/downloaded. All claims remain false until
an independent reviewer actually observes a genuine Setup interface.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

BLOCK = 2048
MIN_ISO = 512 * 1024 * 1024
MAX_ISO = 24 * 1024 * 1024 * 1024
MAX_FRAME = 16 * 1024 * 1024
MAX_LOG = 4 * 1024 * 1024
HASH_CHUNK = 256 * 1024


class Rejected(ValueError):
    pass


def regular_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Rejected("source must be a real regular file, not a symlink or device")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise Rejected("only regular files are supported")
    return path.resolve()


def strict_dir(path):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise Rejected("evidence parent must be an existing real directory")
    return path.resolve()


def sha256_file(path, maximum):
    path = regular_file(path)
    size = path.stat().st_size
    if size == 0 or size > maximum:
        raise Rejected("file is empty or exceeds configured size limit")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while data := stream.read(HASH_CHUNK):
            count += len(data)
            if count > maximum:
                raise Rejected("source length exceeds limit while hashing")
            digest.update(data)
    if count != size or path.stat().st_size != size:
        raise Rejected("source length changed during verification")
    return size, digest.hexdigest()


def media_signature(path):
    """Recognize ISO9660/UDF volume descriptors, not Windows Setup identity."""
    with path.open("rb") as stream:
        stream.seek(16 * BLOCK)
        blocks = stream.read(64 * BLOCK)
    tags = [blocks[n:n+BLOCK] for n in range(0,len(blocks),BLOCK)]
    iso = any(len(t)>6 and t[1:6] == b"CD001" and t[6] == 1 for t in tags)
    udf = any(len(t)>6 and t[1:6] in (b"NSR02",b"NSR03") for t in tags)
    if not (iso or udf):
        raise Rejected("no recognized ISO9660/UDF volume recognition descriptor")
    return {"iso9660DescriptorObserved":iso,"udfRecognitionObserved":udf}


def preflight(iso, operator_sha, minimum=MIN_ISO):
    if not re.fullmatch(r"[0-9a-fA-F]{64}",operator_sha):
        raise Rejected("expected SHA-256 must be exactly 64 hex characters")
    iso = regular_file(iso)
    sz = iso.stat().st_size
    if not minimum <= sz <= MAX_ISO:
        raise Rejected("official media size is outside 512 MiB–24 GiB budget")
    signature = media_signature(iso)
    size, actual = sha256_file(iso, MAX_ISO)
    if actual != operator_sha.lower():
        raise Rejected("operator-supplied ISO SHA-256 does not match source bytes")
    return {"isoBytes":size,"isoSha256":actual,**signature,
            "operatorSha256Matched":True,"publisherProvenanceVerified":False,
            "windowsSetupBootVerified":False,"physicalWriteAuthorized":False}


def firmware():
    for root in (Path("/usr/share/OVMF"),Path("/usr/share/ovmf")):
        for code_name,vars_name in (("OVMF_CODE_4M.fd","OVMF_VARS_4M.fd"),
                                    ("OVMF_CODE.fd","OVMF_VARS.fd")):
            c,v=root/code_name,root/vars_name
            if c.is_file() and v.is_file() and not c.is_symlink() and not v.is_symlink():
                return c,v
    raise Rejected("supported local OVMF firmware files not installed")


def qemu_command(qemu, iso, code, vars_copy, qmp_socket, vnc_socket, serial):
    # QEMU JSON blockdev arguments prevent commas in a legitimate ISO filename
    # from being interpreted as dangerous -drive suboptions.
    file_node=json.dumps({"driver":"file","node-name":"windows_cd_file",
                          "filename":str(iso),"read-only":True},
                         separators=(",",":"))
    raw_node=json.dumps({"driver":"raw","node-name":"windows_cd_raw",
                         "file":"windows_cd_file","read-only":True},
                        separators=(",",":"))
    return [
        str(qemu),"-nodefaults","-machine","q35,accel=tcg","-cpu","qemu64",
        "-m","2048","-smp","2","-no-reboot","-net","none",
        "-sandbox","on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-drive",f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
        "-drive",f"if=pflash,format=raw,unit=1,file={vars_copy}",
        "-blockdev",file_node,
        "-blockdev",raw_node,
        "-device","ich9-ahci,id=ahci",
        "-device","ide-cd,drive=windows_cd_raw,bus=ahci.0",
        "-boot","order=d,menu=off","-vga","std",
        "-vnc",f"unix:{vnc_socket}",
        "-qmp",f"unix:{qmp_socket},server=on,wait=off",
        "-serial",f"file:{serial}",
    ]


def qmp_snapshot(socket_path, filename):
    """Capture a *graphical frame*, never treat it as Setup success."""
    if not socket_path.exists():
        return False
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(socket_path))
        reader=conn.makefile("rb")
        def recv_result():
            for _ in range(24):
                data=reader.readline(65536)
                if not data:
                    raise Rejected("QMP connection closed")
                obj=json.loads(data)
                if "error" in obj:
                    raise Rejected("QMP screenshot failed")
                if "return" in obj:
                    return obj
            raise Rejected("QMP response limit exceeded")
        greeting=reader.readline(65536)
        if not greeting or 'QMP' not in json.loads(greeting):
            raise Rejected('QMP greeting unavailable')
        conn.sendall(b'{"execute":"qmp_capabilities"}\r\n')
        recv_result()
        cmd={"execute":"screendump","arguments":{"filename":str(filename),"format":"ppm"}}
        conn.sendall(json.dumps(cmd).encode()+b"\r\n")
        recv_result()
    if not filename.is_file() or filename.stat().st_size > MAX_FRAME:
        return False
    with filename.open("rb") as stream:
        if stream.read(2) != b"P6":
            return False
    return True


def run_gate(iso, expected, parent, seconds, preflight_only=False, publisher_reference=None):
    if not 30 <= seconds <= 600:
        raise Rejected("VM runtime must be 30 to 600 seconds")
    parent=strict_dir(parent)
    report=preflight(iso,expected)
    if publisher_reference is not None:
        if report["isoSha256"]!=publisher_reference["referenceSha256"]:
            raise Rejected("ISO bytes do not match independent live Microsoft checksum")
    report["publisherChecksumMatched"]=publisher_reference is not None
    report["publisherChecksumReference"]=publisher_reference
    src=regular_file(iso)
    code,vars_template=firmware() if not preflight_only else (None,None)
    if not preflight_only and shutil.which("qemu-system-x86_64") is None:
        raise Rejected("QEMU unavailable: cannot produce boot execution evidence")
    # Evidence directory is created only after all input/hash/firmware checks.
    evidence=Path(tempfile.mkdtemp(prefix="bootnexa-win-acceptance-",dir=parent))
    evidence.chmod(0o700)
    report.update({
        "evidenceSchema":"bootnexa-windows-ovmf-v1",
        "utcStarted":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "virtualOnly":True,
        "physicalWriteAuthorized":False,
        "publisherProvenanceVerified":False,
        "windowsSetupBootVerified":False,
        "graphicalWindowsSetupObserved":False,
        "manualReviewRequired":True,
        "networkConnected":False,
        "hostDiskAttached":False,
        "evidenceDirectory":str(evidence),
        "screenshots":[],
        "bootAttempted":False,
    })
    if preflight_only:
        (evidence/"evidence.json").write_text(json.dumps(report,indent=2)+"\n")
        return report
    with tempfile.TemporaryDirectory(prefix="bootnexa-qemu-iso-") as root:
        temp=Path(root)
        vars_copy=temp/"VARS.fd"
        shutil.copyfile(vars_template,vars_copy)
        qmp=temp/"qmp.sock"
        vnc=temp/"vnc.sock"
        serial=temp/"serial.log"
        logfile=temp/"qemu.log"
        command=qemu_command("qemu-system-x86_64",src,code,vars_copy,qmp,vnc,serial)
        report["ovmfCodeSha256"]=sha256_file(code,32*1024*1024)[1]
        report["ovmfVarsTemplateSha256"]=sha256_file(vars_template,32*1024*1024)[1]
        report["qemuCommandProfile"]="TCG q35 + OVMF + read-only JSON ISO blockdev + unix VNC/QMP + no guest network"
        report["qemuMaximumSeconds"]=seconds
        proc=None
        original_umask=os.umask(0o077)
        try:
            with logfile.open("wb") as log:
                proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,
                    stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                report["bootAttempted"]=True
                began=time.monotonic()
                captured=set()
                while time.monotonic()-began < seconds and proc.poll() is None:
                    elapsed=time.monotonic()-began
                    if logfile.stat().st_size>MAX_LOG:
                        report["failure"]="QEMU stdout exceeded bounded log size"
                        break
                    for phase,at in ((1,8),(2,min(30,seconds//2)),(3,seconds-3)):
                        if phase not in captured and elapsed>=at:
                            captured.add(phase)
                            frame=temp/f"frame-{phase:02d}.ppm"
                            try:
                                if qmp_snapshot(qmp,frame):
                                    dest=evidence/frame.name
                                    shutil.copyfile(frame,dest)
                                    _, digest=sha256_file(dest,MAX_FRAME)
                                    report["screenshots"].append(
                                        {"name":dest.name,"sha256":digest,"format":"PPM"})
                            except (OSError,ValueError,TimeoutError):
                                pass
                    time.sleep(0.25)
                report["qemuElapsedSeconds"]=round(time.monotonic()-began,2)
                report["qemuExitedEarly"]=proc.poll() is not None
                report["qemuExitCode"]=proc.poll()
        finally:
            os.umask(original_umask)
            if proc is not None and proc.poll() is None:
                # Kill whole child process group; do not leave VMs alive.
                os.killpg(proc.pid,signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid,signal.SIGKILL)
                    proc.wait(timeout=5)
            for filename in ("serial.log","qemu.log"):
                source=temp/filename
                if source.is_file() and not source.is_symlink():
                    with source.open("rb") as stream:
                        data=stream.read(MAX_LOG)
                    (evidence/filename).write_bytes(data)
                    report[filename.replace(".log","LogSha256")]=hashlib.sha256(data).hexdigest()
    # Recheck entire ISO after VM execution for modification.
    report["isoUnchangedAfterVm"]=(sha256_file(src,MAX_ISO)==
                                   (report["isoBytes"],report["isoSha256"]))
    if not report["isoUnchangedAfterVm"]:
        report["failure"]="ISO changed during VM execution"
    report["graphicalCaptureSucceeded"]=bool(report["screenshots"])
    report["windowsSetupBootVerified"]=False
    report["manualReviewRequired"]=True
    report["utcFinished"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
    (evidence/"evidence.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso",type=Path,required=True)
    p.add_argument("--sha256",required=True,help="operator-known expected hash; NOT publisher proof")
    p.add_argument("--evidence-parent",type=Path,required=True)
    p.add_argument("--seconds",type=int,default=180)
    p.add_argument("--preflight-only",action="store_true")
    p.add_argument("--microsoft-locale",choices=("English International 64-bit","English 64-bit"),
                   help="fetch exact live Microsoft.com language checksum and require a match")
    args=p.parse_args()
    try:
        official_reference=None
        if args.microsoft_locale:
            import windows_iso_publisher_manifest as publisher
            official_reference=publisher.fetch_publisher_reference(args.microsoft_locale)
        result=run_gate(args.iso,args.sha256,args.evidence_parent,
                        args.seconds,args.preflight_only,official_reference)
    except (Rejected,OSError,subprocess.SubprocessError) as exc:
        print("DENIED: "+str(exc),file=sys.stderr)
        return 1
    print(json.dumps(result,indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
