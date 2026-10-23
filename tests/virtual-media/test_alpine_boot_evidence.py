"""Negative and positive CI-receipt contract tests using disposable tiny regular files."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import alpine_boot_evidence as evidence


class AlpineBootEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.output = self.path / "virtual.img"
        self.output.write_bytes(b"virtual-file-only-fixture")
        self.digest = hashlib.sha256(self.output.read_bytes()).hexdigest()
        self.serial = self.path / "guest-serial.log"
        self.serial.write_bytes(b"Booting virtual Alpine\r\nlocalhost login: ")
        self.firmware = self.path / "OVMF_CODE.fd"
        self.firmware.write_bytes(b"synthetic firmware test bytes")
        self.report = self.path / "report.json"
        self.native = {
            "virtualOnly": True,
            "physicalWriteAuthorized": False,
            "outputPath": str(self.output),
            "outputSha256": self.digest,
            "media": {
                "virtualOnly": True,
                "physicalWriteAuthorized": False,
                "distroProfile": evidence.PROFILE,
                "imageBytes": len(self.output.read_bytes()),
                "publisherSha256Matched": True,
                "mbrEfiPartitionVerified": True,
                "fatEfiBootloaderVerified": True,
                "sourceSha256": self.digest,
                "copiedSha256": self.digest,
                "bootExecutionVerified": False,
                "linuxDistributionBootVerified": False,
            },
        }
        self.write_native()
        small = patch.object(evidence, "EXPECTED_BYTES", self.output.stat().st_size)
        checksum = patch.object(evidence, "EXPECTED_SHA256", self.digest)
        version = patch.object(evidence.subprocess, "check_output",
                               return_value="QEMU emulator version test-fixture\n")
        for active in (small, checksum, version):
            active.start()
            self.addCleanup(active.stop)

    def write_native(self):
        self.report.write_text(json.dumps(self.native), encoding="utf-8")

    def generate(self, profile=evidence.PROFILE):
        return evidence.produce_evidence(self.report, self.serial, self.firmware,
                                         self.path, "a" * 40, profile)

    def test_ci_receipt_is_explicitly_virtual_and_contains_no_local_paths(self):
        receipt = self.generate()
        self.assertTrue(receipt["bootExecutionVerified"])
        self.assertTrue(receipt["linuxDistributionBootVerified"])
        self.assertFalse(receipt["physicalWriteAuthorized"])
        self.assertFalse(receipt["physicalUsbBootVerified"])
        self.assertTrue(receipt["readbackVerified"])
        self.assertNotIn(str(self.path), json.dumps(receipt))
        self.assertEqual(json.loads((self.path / "alpine-boot-evidence.json").read_text()), receipt)

    def test_missing_login_fails_without_claiming_boot(self):
        self.serial.write_bytes(b"OVMF EFI bootloader started, no operating system")
        with self.assertRaisesRegex(ValueError, "login"):
            self.generate()
        self.assertFalse((self.path / "alpine-boot-evidence.json").exists())

    def test_corrupt_post_boot_output_fails_readback(self):
        self.output.write_bytes(b"X" + self.output.read_bytes()[1:])
        with self.assertRaisesRegex(ValueError, "changed|hash"):
            self.generate()

    def test_native_unauthorised_physical_write_claim_fails(self):
        self.native["physicalWriteAuthorized"] = True
        self.write_native()
        with self.assertRaisesRegex(ValueError, "physical authority"):
            self.generate()

    def test_native_cli_claiming_os_boot_fails(self):
        self.native["media"]["bootExecutionVerified"] = True
        self.write_native()
        with self.assertRaisesRegex(ValueError, "boot success"):
            self.generate()

    def test_symlink_serial_log_fails(self):
        real = self.path / "other.log"
        real.write_bytes(self.serial.read_bytes())
        self.serial.unlink()
        self.serial.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "missing serial"):
            self.generate()

    def test_different_profile_fails_even_with_matching_digest(self):
        self.native["media"]["distroProfile"] = "alpine-virt-other"
        self.write_native()
        with self.assertRaisesRegex(ValueError, "publisher-pinned"):
            self.generate()

    def test_existing_success_receipt_cannot_be_overwritten(self):
        original = self.generate()
        with self.assertRaises(FileExistsError):
            self.generate()
        self.assertEqual(
            json.loads((self.path / "alpine-boot-evidence.json").read_text()),
            original,
        )

    def test_versioned_firmware_symlink_hashes_real_firmware(self):
        source = self.firmware
        link = self.path / "OVMF_CURRENT.fd"
        link.symlink_to(source)
        self.firmware = link
        receipt = self.generate()
        self.assertEqual(
            receipt["firmwareSha256"],
            hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    def test_second_pinned_profile_produces_distinct_virtual_only_evidence(self):
        self.native["media"]["distroProfile"] = evidence.PROFILE_3241
        self.write_native()
        with patch.object(evidence, "EXPECTED_SHA256_3241", self.digest), \
                patch.object(evidence, "EXPECTED_BYTES_3241", self.output.stat().st_size):
            receipt = self.generate(profile=evidence.PROFILE_3241)
            self.assertEqual(receipt["profile"], evidence.PROFILE_3241)
            self.assertFalse(receipt["physicalWriteAuthorized"])
            self.assertFalse(receipt["physicalUsbBootVerified"])

    def test_cross_profile_digest_mismatch_fails(self):
        self.native["media"]["distroProfile"] = evidence.PROFILE_3241
        self.write_native()
        with self.assertRaisesRegex(ValueError, "publisher-pinned"):
            self.generate(profile=evidence.PROFILE_3241)

    def test_unknown_profile_is_rejected_before_any_receipt(self):
        with self.assertRaisesRegex(ValueError, "unlisted"):
            self.generate(profile="alpine-standard-any")
        self.assertFalse((self.path / "alpine-boot-evidence.json").exists())

    def test_wrong_or_missing_git_revision_rejected(self):
        with self.assertRaisesRegex(ValueError, "commit identity"):
            evidence.produce_evidence(self.report, self.serial, self.firmware, self.path, "main")


if __name__ == "__main__":
    unittest.main()
