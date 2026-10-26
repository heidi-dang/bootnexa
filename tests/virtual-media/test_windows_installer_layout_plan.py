"""Adversarial Windows ISO manifest -> virtual GPT/FAT32 layout planning tests."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MOD=Path(__file__).with_name("windows_installer_layout_plan.py")
spec=importlib.util.spec_from_file_location("layout_plan",MOD)
plan=importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)

SHA="a"*64
def fixture(install_bytes=2*plan.GIB,extension="WIM"):
    records=[
        ("EFI/BOOT/BOOTX64.EFI",100*1024),
        ("EFI/MICROSOFT/BOOT/BCD",64*1024),
        ("SOURCES/BOOT.WIM",600*plan.MIB),
        ("SETUP.EXE",30*plan.MIB),
        (f"SOURCES/INSTALL.{extension}",install_bytes),
        ("BOOT/BOOT.SDI",4*plan.MIB),
    ]
    return {
        "schema":"bootnexa-official-iso-manifest-v1",
        "sourceBytes":min(24*plan.GIB,install_bytes+1*plan.GIB),
        "sourceSha256":SHA,
        "publisherChecksumMatched":True,
        "isoSourceUnchanged":True,
        "allListedFilesIndependentlyHashed":True,
        "windowsSetupBootVerified":False,
        "physicalWriteAuthorized":False,
        "installerCompatibleVerified":False,
        "publisherChecksumReference":{
            "sourceUrl":plan.source_gate.OFFICIAL_URL,
            "locale":"English International 64-bit",
            "referenceSha256":SHA,
        },
        "listedFileCount":len(records),
        "files":[{"path":p,"bytes":n,"sha256":"b"*64}
                 for p,n in records],
    }

class LayoutTest(unittest.TestCase):
    def test_small_wim_fat32_fit_remains_non_actionable(self):
        result=plan.estimate_layout(fixture(),8,"c"*64)
        self.assertEqual(result["installationPayloadKind"],"WIM")
        self.assertFalse(result["requiresSplitWim"])
        self.assertEqual(result["estimatedSplitPartsNotGuaranteed"],None)
        self.assertTrue(result["virtualOnly"] and result["readOnly"])
        self.assertFalse(result["manifestAssertionsTrusted"])
        self.assertFalse(result["actionable"])
        self.assertFalse(result["virtualDiskGenerated"])
        self.assertFalse(result["physicalWriteAuthorized"])
        self.assertFalse(result["windowsSetupBootVerified"])
        self.assertEqual(result["proposedDiskCapacityBytes"],8*plan.GIB)
        self.assertEqual(result["inputFileCount"],6)
        self.assertIn("complete_real_iso_to_virtual_disk_staging_unimplemented",
                      result["blockers"])
    def test_single_file_fat32_boundary_and_wimlib_proposal(self):
        fit=plan.estimate_layout(fixture(plan.MAX_FAT32_FILE),8)
        self.assertFalse(fit["requiresSplitWim"])
        too_big=plan.estimate_layout(fixture(plan.MAX_FAT32_FILE+1),8)
        self.assertTrue(too_big["requiresSplitWim"])
        self.assertEqual(too_big["proposedWimlibSplitTargetBytes"],3800*plan.MIB)
        self.assertFalse(too_big["actualSplitWimArtifactsVerified"])
        self.assertFalse(too_big["splitWimFilesGenerated"])
        self.assertIn("verified_swm_split_and_genuine_large_payload_staging_not_qualified",
                      too_big["blockers"])
        self.assertGreater(too_big["estimatedSplitPayloadBudgetBytes"],
                           plan.MAX_FAT32_FILE)
        self.assertTrue(all(item["bytes"]<=plan.MAX_FAT32_FILE or
                            item.get("stageAction")=="replace_with_verified_swm"
                            for item in too_big["filePlacements"]))
    def test_oversized_esd_and_other_file_are_blocked(self):
        oversized=plan.estimate_layout(fixture(plan.MAX_FAT32_FILE+1,"ESD"),8)
        self.assertFalse(oversized["requiresSplitWim"])
        self.assertIn("oversized_esd_without_independently_qualified_conversion",
                      oversized["blockers"])
        image=fixture()
        image["files"].append({"path":"SOURCES/UNSUPPORTED.DAT",
                               "bytes":plan.MAX_FAT32_FILE+1,
                               "sha256":"b"*64})
        image["listedFileCount"]+=1
        result=plan.estimate_layout(image,12)
        self.assertIn("other_iso_file_exceeds_fat32_single_file_limit",
                      result["blockers"])
    def test_capacity_gates_and_efi_headroom(self):
        too_small=plan.estimate_layout(fixture(4*plan.GIB+1),1)
        self.assertIn("fat32_payload_partition_capacity_exceeded",too_small["blockers"])
        img=fixture()
        img["files"][0]["bytes"]=255*plan.MIB
        result=plan.estimate_layout(img,8)
        self.assertIn("efi_partition_capacity_exceeded",result["blockers"])
        for n in (0,25,-1,2.5,True):
            with self.assertRaises(plan.Refused):
                plan.estimate_layout(fixture(),n)
    def test_collisions_directory_file_and_reserved_names_rejected(self):
        for extra in ["setup.exe","EFI/BOOT/bootx64.efi",
                      "SETUP.EXE/CHILD","CON.TXT","EFI/../TRAVERSE",
                      "A\\B","SOURCES/INSTALL2.SWM",
                      "EFI/BOOT/BAD.","AUX","EFI//BAD"]:
            image=fixture()
            image["files"].append({"path":extra,"bytes":3,"sha256":"c"*64})
            image["listedFileCount"]+=1
            with self.assertRaises(plan.Refused,msg=extra):
                plan.estimate_layout(image,8)
    def test_forged_or_inconsistent_manifest_is_never_authority(self):
        image=fixture()
        for field,value in (
            ("sourceSha256","bad"),
            ("publisherChecksumMatched",False),
            ("isoSourceUnchanged",False),
            ("allListedFilesIndependentlyHashed",False),
            ("physicalWriteAuthorized",True),
            ("installerCompatibleVerified",True),
            ("windowsSetupBootVerified",True),
            ("listedFileCount",9999),
        ):
            copy_=copy.deepcopy(image)
            copy_[field]=value
            with self.assertRaises(plan.Refused,msg=field):
                plan.estimate_layout(copy_,8)
        copy_=copy.deepcopy(image)
        copy_["publisherChecksumReference"]["sourceUrl"]="https://example.org"
        with self.assertRaises(plan.Refused):
            plan.estimate_layout(copy_,8)
        copy_=copy.deepcopy(image)
        copy_["publisherChecksumReference"]["referenceSha256"]="f"*64
        with self.assertRaises(plan.Refused):
            plan.estimate_layout(copy_,8)
        for extension in ("WIM","ESD"):
            extra=copy.deepcopy(image)
            extra["files"].append({"path":f"SOURCES/INSTALL.{extension}",
                                   "bytes":3,"sha256":"b"*64})
            extra["listedFileCount"]+=1
            if extension=="ESD":
                with self.assertRaises(plan.Refused):
                    plan.estimate_layout(extra,8)
    def test_missing_required_install_file_and_overflow(self):
        for missing in ("SETUP.EXE","EFI/BOOT/BOOTX64.EFI","SOURCES/INSTALL.WIM"):
            doc=fixture()
            doc["files"]=[x for x in doc["files"] if x["path"]!=missing]
            doc["listedFileCount"]=len(doc["files"])
            with self.assertRaises(plan.Refused):
                plan.estimate_layout(doc,8)
        doc=fixture()
        doc["files"].append({"path":"EXTRA.TXT",
                             "bytes":plan.source_gate.MAX_FILE+1,"sha256":"b"*64})
        doc["listedFileCount"]+=1
        with self.assertRaises(plan.Refused):
            plan.estimate_layout(doc,8)
    def test_file_manifest_only_accepted_from_regular_json_and_never_trusted(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"manifest.json"
            path.write_text(json.dumps(fixture()))
            input_,digest=plan.read_manifest(path)
            result=plan.estimate_layout(input_,8,digest)
            self.assertEqual(result["inputManifestSha256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertFalse(result["manifestAssertionsTrusted"])
            alias=Path(temp)/"alias"
            alias.symlink_to(path)
            with self.assertRaises(plan.Refused):
                plan.read_manifest(alias)
            path.write_bytes(b"{" + b" "*(plan.MAX_PLAN_JSON+1))
            with self.assertRaises(plan.Refused):
                plan.read_manifest(path)

if __name__=="__main__":
    unittest.main()
