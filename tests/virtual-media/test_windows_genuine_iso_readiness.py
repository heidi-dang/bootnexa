"""Readiness is policy only; no Microsoft ISO, QEMU or media writes."""
import hashlib
from pathlib import Path
import tempfile
import unittest

import windows_genuine_iso_readiness as readiness


class GenuineIsoReadinessTests(unittest.TestCase):
    def fake_reference(self,source):
        return lambda locale:{
            "referenceSha256":hashlib.sha256(source).hexdigest(),
            "locale":locale,
            "sourceUrl":"synthetic test reference, never Microsoft",
        }

    def test_no_source_no_tools_never_claims_setup(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            report=readiness.inspect(None,"English 64-bit",tmp,
                get_reference=self.fake_reference(b"not a real ISO"),
                find_executable=lambda name:None,
                firmware_check=lambda:False,native_binary=Path(tmp)/"missing",
                capability_probe=lambda p:False)
            self.assertFalse(report["dataTransferReadyForOperator"])
            self.assertFalse(report["guestCaptureReadyForOperator"])
            self.assertFalse(report["publisherReferenceFromLiveMicrosoft"])
            self.assertIn("operator_supplied_authentic_iso_missing",
                          report["dataTransferBlockers"])
            self.assertIn("qemu_guest_execution_unavailable",
                          report["guestEvidenceBlockers"])
            self.assertFalse(report["physicalWriteAuthorized"])

    def test_source_digest_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp)
            iso=root/"fixture.iso"
            iso.write_bytes(b"synthetic source")
            executable=root/"bootnexa-media"
            executable.write_bytes(b"test native stub")
            executable.chmod(0o700)
            report=readiness.inspect(iso,"English International 64-bit",root,
                get_reference=self.fake_reference(b"other synthetic bytes"),
                find_executable=lambda n:"/synthetic/exe",
                firmware_check=lambda:True,minimum_iso_bytes=1,
                native_binary=executable,capability_probe=lambda p:True)
            self.assertFalse(report["dataTransferReadyForOperator"])
            self.assertFalse(report["isoSha256MatchedReference"])
            self.assertIn("iso_sha256_does_not_match_live_microsoft_reference",
                          report["dataTransferBlockers"])

    def test_synthetic_matching_digest_can_only_prove_host_and_test_reference(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp)
            payload=b"unit test source"
            iso=root/"fixture.iso"
            iso.write_bytes(payload)
            exe=root/"native"
            exe.write_bytes(b"test only")
            exe.chmod(0o700)
            report=readiness.inspect(iso,"English 64-bit",root,
                get_reference=self.fake_reference(payload),
                find_executable=lambda n:"/synthetic/exe",
                firmware_check=lambda:True,minimum_iso_bytes=1,
                native_binary=exe,capability_probe=lambda p:True)
            self.assertTrue(report["isoSha256MatchedReference"])
            self.assertFalse(report["dataTransferReadyForOperator"])
            self.assertIn("test_reference_is_not_live_microsoft_provenance",
                          report["dataTransferBlockers"])
            self.assertFalse(report["publisherReferenceFromLiveMicrosoft"])
            self.assertFalse(report["windowsSetupBootVerified"])
            self.assertFalse(report["actualSourceBoundStagingExecuted"])
            self.assertFalse(report["installerCompatibleVerified"])

    def test_outdated_binary_is_not_considered_ready(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp)
            old=root/"old-binary"
            old.write_text("stale executable file")
            old.chmod(0o700)
            report=readiness.inspect(None,"English 64-bit",root,
                get_reference=self.fake_reference(b"not Microsoft"),
                find_executable=lambda n:"/synthetic/exe",
                firmware_check=lambda:True,native_binary=old,
                capability_probe=lambda p:False)
            self.assertTrue(report["nativeReleaseCliPresent"])
            self.assertFalse(report["nativeCombinedCapabilityVerified"])
            self.assertIn("release_native_cli_missing_current_combined_capability",
                          report["dataTransferBlockers"])

    def test_native_capability_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            fake=Path(tmp)/"fake"
            fake.write_text("#!/bin/sh\nprintf '{}\\n'\n")
            fake.chmod(0o700)
            self.assertFalse(readiness.native_combined_capability(fake))

    def test_memory_reserve_blocks_undersized_host_even_with_guest_tools(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp)
            report=readiness.inspect(None,"English 64-bit",root,
                get_reference=self.fake_reference(b"synthetic only"),
                find_executable=lambda name:"/packaged/tool",
                firmware_check=lambda:True,
                native_binary=root/"missing",
                guest_memory_probe=lambda:2*readiness.GIB)
            self.assertEqual(report["guestHostMemAvailableBytes"],2*readiness.GIB)
            self.assertIn("host_memavailable_below_qemu_safety_floor",
                          report["guestEvidenceBlockers"])
            self.assertFalse(report["guestEvidenceHostReady"])

    def test_user_owned_ovmf_override_rejects_symlink(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp)
            own=root/"firmware"
            own.mkdir()
            (own/"OVMF_CODE_4M.fd").write_bytes(b"test-code")
            (own/"OVMF_VARS_4M.fd").write_bytes(b"test-vars")
            with patch.dict("os.environ",{"BOOTNEXA_OVMF_DIR":str(own)}):
                self.assertTrue(readiness.firmware_available())
            link=root/"linked"
            link.symlink_to(own,target_is_directory=True)
            with patch.dict("os.environ",{"BOOTNEXA_OVMF_DIR":str(link)}):
                self.assertFalse(readiness.firmware_available())

    def test_symlink_iso_and_scratch_refused(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp)
            iso=root/"fixture.iso"
            iso.write_bytes(b"test")
            shortcut=root/"linked.iso"
            shortcut.symlink_to(iso)
            scratch=root/"linked-scratch"
            scratch.symlink_to(root,target_is_directory=True)
            result=readiness.inspect(shortcut,"English 64-bit",scratch,
                get_reference=self.fake_reference(b"test"),
                find_executable=lambda n:None,firmware_check=lambda:False,
                capability_probe=lambda p:False)
            self.assertFalse(result["scratchParentValid"])
            self.assertFalse(result["isoSourcePresentAndSizeAllowed"])
            self.assertFalse(result["dataTransferReadyForOperator"])
            self.assertEqual(result["isoSourceSha256"],None)


if __name__=="__main__":
    unittest.main()
