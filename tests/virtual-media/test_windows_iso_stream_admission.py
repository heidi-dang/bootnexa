"""Large ISO transfer admission policy tests: no emulator, no ISO, no host writes."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

module=Path(__file__).with_name("windows_iso_virtual_fat32_stream.py")
spec=importlib.util.spec_from_file_location("bounded_iso_stage",module)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
MIB=1024**2

class StreamAdmissionTest(unittest.TestCase):
    def check(self,free,total=48*MIB,capacity=1):
        return stage.verify_temporary_storage_admission(
            total,capacity,tempdir="/tmp",
            statvfs=lambda _: SimpleNamespace(f_bavail=free//4096,
                                               f_frsize=4096))
    def test_budget_increases_but_remains_bounded(self):
        self.assertEqual(stage.MAX_FILE,128*MIB)
        self.assertEqual(stage.MAX_TOTAL,384*MIB)
        self.assertEqual(stage.MAX_FILES,128)
        self.assertTrue(self.check(1024*MIB)["anonymousStorageAdmissionPassed"])
        self.assertEqual(self.check(1024*MIB)["requiredFreeHostBytesAtAdmission"],512*MIB)
        self.assertGreaterEqual(self.check(1024*MIB,total=384*MIB,capacity=1)
                                ["requiredFreeHostBytesAtAdmission"],1024*MIB)
        for total in (-1,stage.MAX_TOTAL+1,True):
            with self.assertRaises(stage.Refused):
                self.check(2*1024*MIB,total=total)
    def test_low_free_host_storage_blocks_before_disk(self):
        for free in (0,120*MIB,511*MIB):
            with self.assertRaisesRegex(stage.Refused,"insufficient host free"):
                self.check(free)
        with self.assertRaisesRegex(stage.Refused,"insufficient host free"):
            self.check(1000*MIB,total=384*MIB)
        for gib in (0,25,-1,True):
            with self.assertRaises(stage.Refused):
                self.check(2048*MIB,capacity=gib)
    def test_virtual_partition_capacity_and_staging_manifest_bounds(self):
        mock=[
            {"path":"EFI/BOOT/BOOTX64.EFI","bytes":512,"sha256":"a"*64},
            {"path":"SOURCES/BOOT.WIM","bytes":1024,"sha256":"a"*64},
            {"path":"SETUP.EXE","bytes":64,"sha256":"a"*64},
            {"path":"SOURCES/INSTALL.WIM","bytes":96*MIB,"sha256":"a"*64},
        ]
        actual,count=stage.validated_files({"files":mock})
        self.assertEqual(len(actual),4)
        self.assertGreater(count,32*MIB)
        mock[3]["bytes"]=128*MIB+1
        with self.assertRaises(stage.Refused):
            stage.validated_files({"files":mock})
        mock[3]["bytes"]=128*MIB
        for item in mock:
            item["bytes"]=128*MIB
        with self.assertRaises(stage.Refused):
            stage.validated_files({"files":mock})  # 512 MiB exceeds 384 MiB

if __name__=="__main__":
    unittest.main()
