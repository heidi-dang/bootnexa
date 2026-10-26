"""Adversarial ISO->Rust pipe tests with no media, filesystem or device writes."""
import importlib.util
from pathlib import Path
import os
import subprocess
import sys
import time
import unittest

path=Path(__file__).with_name("windows_iso_virtual_fat32_stream.py")
spec=importlib.util.spec_from_file_location("iso_pipe",path)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class IsoPipeSafetyTest(unittest.TestCase):
    def child(self,code):
        return subprocess.Popen(
            [sys.executable,"-u","-c",code],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    def cleanup_child(self,child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        for pipe in (child.stdin,child.stdout,child.stderr):
            pipe.close()

    def test_nonreading_child_cannot_block_write_indefinitely(self):
        child=self.child("import time; time.sleep(20)")
        try:
            os.set_blocking(child.stdin.fileno(),False)
            start=time.monotonic()
            with self.assertRaisesRegex(stage.Refused,"deadline"):
                stage._send_to_disk(child,b"X"*(4*1024*1024),
                                    time.monotonic()+0.25)
            self.assertLess(time.monotonic()-start,2)
        finally:
            self.cleanup_child(child)

    def test_early_child_exit_refused(self):
        child=self.child("raise SystemExit(7)")
        try:
            child.wait(timeout=3)
            os.set_blocking(child.stdin.fileno(),False)
            with self.assertRaises(stage.Refused):
                stage._send_to_disk(child,b"X"*100,time.monotonic()+1)
        finally:
            self.cleanup_child(child)

    def test_simultaneously_drains_both_output_pipes(self):
        child=self.child(
            "import sys; "
            "sys.stderr.buffer.write(b'e'*60000); "
            "sys.stdout.buffer.write(b' '*250000+b'{\"ok\":true}')")
        try:
            child.stdin.close()
            self.assertEqual(stage._collect_disk_report(
                child,time.monotonic()+3),{"ok":True})
        finally:
            self.cleanup_child(child)

    def test_rejects_unbounded_stdout_and_stderr(self):
        for channel,count in (("stdout",1024*1024+1),("stderr",65537)):
            with self.subTest(channel=channel):
                child=self.child(
                    "import sys; sys.%s.buffer.write(b'A'*%d)"
                    % (channel,count))
                try:
                    child.stdin.close()
                    with self.assertRaisesRegex(stage.Refused,"byte budget"):
                        stage._collect_disk_report(child,time.monotonic()+3)
                finally:
                    self.cleanup_child(child)

    def test_report_timeout_even_after_stdout_eof(self):
        child=self.child("import time; time.sleep(20)")
        try:
            child.stdin.close()
            start=time.monotonic()
            with self.assertRaisesRegex(stage.Refused,"deadline"):
                stage._collect_disk_report(child,time.monotonic()+0.25)
            self.assertLess(time.monotonic()-start,2)
        finally:
            self.cleanup_child(child)


if __name__=="__main__":
    unittest.main()
