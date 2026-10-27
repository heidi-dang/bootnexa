"""Read-only Windows ISO evidence gate contract tests; no proprietary media."""
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

MODULE=Path(__file__).with_name("windows_setup_ovmf_gate.py")
spec=importlib.util.spec_from_file_location("windows_setup_ovmf_gate",MODULE)
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def fixture(path):
    # Tiny descriptor-only ISO fixture for unit tests; the public production
    # CLI still enforces 512 MiB minimum and never treats it as Windows Setup.
    data=bytearray(96*2048)
    data[16*2048]=1
    data[16*2048+1:16*2048+6]=b"CD001"
    data[16*2048+6]=1
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class SetupGateTest(unittest.TestCase):
    def test_sha_and_iso_descriptor_preflight_is_not_publisher_proof(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"synthetic.iso"
            expected=fixture(path)
            report=gate.preflight(path,expected,minimum=1024)
            self.assertTrue(report["operatorSha256Matched"])
            self.assertTrue(report["iso9660DescriptorObserved"])
            self.assertFalse(report["publisherProvenanceVerified"])
            self.assertFalse(report["windowsSetupBootVerified"])
            self.assertFalse(report["physicalWriteAuthorized"])
            with self.assertRaises(gate.Rejected):
                gate.preflight(path,"0"*64,minimum=1024)
            with self.assertRaises(gate.Rejected):
                gate.preflight(path,"zzz",minimum=1024)
            with self.assertRaises(gate.Rejected):
                gate.preflight(path,expected)  # public minimum is 512 MiB

    def test_reject_malformed_volume_symlink_and_output_parent(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)
            image=parent/"bad.iso"
            image.write_bytes(b"\0"*(96*2048))
            expected=hashlib.sha256(image.read_bytes()).hexdigest()
            with self.assertRaises(gate.Rejected):
                gate.preflight(image,expected,minimum=1024)
            valid=parent/"valid.iso"
            digest=fixture(valid)
            linked=parent/"linked.iso"
            linked.symlink_to(valid)
            with self.assertRaises(gate.Rejected):
                gate.preflight(linked,digest,minimum=1024)
            dest=parent/"linked-evidence"
            dest.symlink_to(parent,target_is_directory=True)
            with self.assertRaises(gate.Rejected):
                gate.strict_dir(dest)
            self.assertEqual(len(list(parent.glob("bootnexa-win-acceptance-*"))),0)

    def test_publisher_checksum_mismatch_refused_before_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            iso=root/"sparse-descriptor.iso"
            with iso.open("wb") as f:
                f.truncate(512*1024*1024)
                f.seek(16*2048)
                f.write(b"\x01CD001\x01")
            with iso.open("rb") as f:
                digest=hashlib.file_digest(f,"sha256").hexdigest()
            source={"locale":"English 64-bit","referenceSha256":"0"*64}
            with self.assertRaises(gate.Rejected):
                gate.run_gate(iso,digest,root,30,preflight_only=True,
                              publisher_reference=source)
            self.assertFalse(list(root.glob("bootnexa-win-acceptance-*")))
            source["referenceSha256"]=digest
            report=gate.run_gate(iso,digest,root,30,preflight_only=True,
                                 publisher_reference=source)
            self.assertTrue(report["publisherChecksumMatched"])
            self.assertFalse(report["publisherProvenanceVerified"])
            self.assertFalse(report["windowsSetupBootVerified"])
            self.assertTrue(Path(report["evidenceDirectory"]).joinpath("evidence.json").exists())

    def test_guest_memory_admission_avoids_oom_pressure(self):
        self.assertEqual(gate.guest_memory_available("MemAvailable: 4194304 kB\n"),
                         4*1024**3)
        self.assertIsNone(gate.guest_memory_available("MemFree: 500 kB\n"))
        with self.assertRaises(gate.Rejected):
            gate.admit_guest_memory(2*1024**3)
        self.assertEqual(gate.admit_guest_memory(4*1024**3),4*1024**3)

    def test_explicit_packaged_ovmf_directory_and_link_refusal(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            root=Path(folder)
            fw=root/"fw"
            fw.mkdir()
            code=fw/"OVMF_CODE_4M.fd"
            variables=fw/"OVMF_VARS_4M.fd"
            code.write_bytes(b"synthetic-firmware-code")
            variables.write_bytes(b"synthetic-vars")
            with patch.dict("os.environ",{"BOOTNEXA_OVMF_DIR":str(fw)}):
                self.assertEqual(gate.firmware(),(code,variables))
            link=root/"linked"
            link.symlink_to(fw,target_is_directory=True)
            with patch.dict("os.environ",{"BOOTNEXA_OVMF_DIR":str(link)}):
                with self.assertRaises(gate.Rejected):
                    gate.firmware()

    def test_command_has_only_readonly_iso_and_unix_monitor(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            tricky=root/"windows,image;not-a-device.iso"
            command=gate.qemu_command(
                "qemu-system-x86_64",tricky,
                root/"CODE.fd",root/"VARS.fd",root/"qmp.sock",
                root/"vnc.sock",root/"serial.log")
            self.assertEqual(command[0],"qemu-system-x86_64")
            self.assertEqual(command[command.index("-net")+1],"none")
            self.assertEqual(command[command.index("-vnc")+1],
                             f"unix:{root/'vnc.sock'}")
            self.assertIn("-sandbox",command)
            self.assertIn("-nodefaults",command)
            self.assertNotIn("-hda",command)
            self.assertNotIn("-usb",command)
            self.assertNotIn("-enable-kvm",command)
            self.assertEqual(command.count("-blockdev"),2)
            nodes=[]
            for i,argument in enumerate(command):
                if argument=="-blockdev":
                    self.assertTrue(command[i+1].startswith("{"))
                    nodes.append(json.loads(command[i+1]))
            self.assertEqual(nodes[0]["filename"],str(tricky))
            self.assertTrue(all(node["read-only"] for node in nodes))
            self.assertEqual(nodes[1]["driver"],"raw")
            self.assertFalse(any("/dev/sd" in str(arg) for arg in command))

    def test_qmp_screendump_protocol_is_metadata_not_setup_attestation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            sock=root/"qmp.sock"
            frame=root/"frame.ppm"
            server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            server.bind(str(sock))
            server.listen(1)
            seen=[]
            def responder():
                conn,_=server.accept()
                with conn:
                    conn.sendall(b'{"QMP":{"version":{"qemu":{"major":9}}}}\r\n')
                    buf=conn.makefile("rb")
                    for count in range(2):
                        action=json.loads(buf.readline())
                        seen.append(action["execute"])
                        if action["execute"]=="screendump":
                            destination=Path(action["arguments"]["filename"])
                            destination.write_bytes(b"P6\n1 1\n255\n\x00\x00\x00")
                        conn.sendall(b'{"return":{}}\r\n')
                server.close()
            worker=threading.Thread(target=responder,daemon=True)
            worker.start()
            self.assertTrue(gate.qmp_snapshot(sock,frame))
            worker.join(timeout=2)
            self.assertEqual(seen,["qmp_capabilities","screendump"])
            self.assertTrue(frame.is_file())
            self.assertNotIn("windowsSetupBootVerified",seen)


if __name__=="__main__":
    unittest.main()
