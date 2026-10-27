"""Adversarial source binding and preflight policy; no ISO media required."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

from test_windows_installer_layout_plan import fixture

p=Path(__file__).with_name("windows_source_bound_combined_iso.py")
spec=importlib.util.spec_from_file_location("sourcebound_combined",p)
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class SourceBoundCombinedPolicy(unittest.TestCase):
    def test_real_manifest_five_gib_wim_fits_and_removes_wim_from_stream(self):
        doc=fixture(5*gate.GIB)
        install,other,total=gate.validated_remainder(doc,16)
        self.assertEqual(install["path"],"SOURCES/INSTALL.WIM")
        self.assertEqual(len(other),5)
        self.assertEqual(total,sum(x["bytes"] for x in other))
        self.assertTrue(all(x["path"].casefold()!="sources/install.wim" for x in other))

    def test_deny_install_esd_ambiguous_swm_and_unsafe_names(self):
        base=fixture(5*gate.GIB)
        for path in ("SOURCES/install.esd","SOURCES/INSTALL2.SWM",
                     "EFI/BOOT/bootx64.efi", "../PWN", "AUX.TXT",
                     "setup.exe/CHILD", "SOURCES/INSTALL.wim/CHILD",
                     "EFI/BAD | NAME"):
            doc=copy.deepcopy(base)
            doc["files"].append({"path":path,"bytes":12,"sha256":"b"*64})
            with self.subTest(path=path),self.assertRaises(gate.Refused):
                gate.validated_remainder(doc,16)

    def test_reject_wrong_capacity_and_large_remainder(self):
        doc=fixture(5*gate.GIB)
        for gib in (0,7,25,True):
            with self.subTest(disk=gib),self.assertRaises(gate.Refused):
                gate.validated_remainder(doc,gib)
        doc["files"][2]["bytes"]=gate.GIB+1
        with self.assertRaises(gate.Refused):
            gate.validated_remainder(doc,16)
        doc=fixture(5*gate.GIB)
        doc["files"][2]["bytes"]=gate.GIB
        doc["files"][3]["bytes"]=gate.GIB
        doc["files"][5]["bytes"]=gate.GIB
        with self.assertRaises(gate.Refused):
            gate.validated_remainder(doc,16)

    def test_scratch_storage_and_invalid_sizes(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            admission=gate.space_admission(folder,32*gate.MIB,1000,8)
            self.assertGreater(admission["availableHostBytesAtPreflight"],
                               admission["requiredScratchBytesAtPreflight"])
            for source,rest,size in ((0,0,8),(17*gate.GIB,0,24),
                                     (gate.GIB,3*gate.GIB,16),
                                     (7*gate.GIB,0,8)):
                with self.subTest(source=source,rest=rest,size=size):
                    with self.assertRaises(gate.Refused):
                        gate.space_admission(folder,source,rest,size)
        self.assertEqual(gate.MAGIC,b"BNXI0002")


if __name__=="__main__":
    unittest.main()
