"""Untrusted official-manifest snapshots cannot enable virtual media writes."""
from pathlib import Path
import copy
import importlib.util
import unittest

from test_windows_installer_layout_plan import fixture

path = Path(__file__).with_name("windows_official_compatibility_gate.py")
spec = importlib.util.spec_from_file_location("official_gate", path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class OfficialCompatibilityTest(unittest.TestCase):
    def test_5gib_wim_snapshot_is_feasible_but_never_authorized(self):
        doc = fixture(5*gate.GIB)
        report = gate.assess(doc, 16)
        self.assertTrue(report["syntheticCombinedProfileCapacityFeasible"])
        self.assertFalse(report["safeToExecute"])
        self.assertFalse(report["manifestAssertionsTrusted"])
        self.assertFalse(report["officialMicrosoftIsoProcessed"])
        self.assertFalse(report["physicalWriteAuthorized"])
        self.assertGreater(len(report["unverifiedAcceptanceGates"]), 3)

    def test_esd_and_unsupported_non_install_sources_report_blockers(self):
        report=gate.assess(fixture(5*gate.GIB, "ESD"),16)
        self.assertIn("combined_swm_profile_does_not_handle_install_esd",
                      report["feasibilityBlockers"])
        too_large=fixture(5*gate.GIB)
        too_large["files"][2]["bytes"]=gate.GIB+1
        report=gate.assess(too_large,16)
        self.assertIn("non_install_file_exceeds_1gib_stream_policy",
                      report["feasibilityBlockers"])
        small=gate.assess(fixture(5*gate.GIB), 1)
        self.assertIn("combined_profile_requires_8gib_minimum",small["feasibilityBlockers"])

    def test_missing_and_forged_manifest_claims_are_denied(self):
        for change in [
            ("publisherChecksumMatched", False),
            ("physicalWriteAuthorized", True),
            ("isoSourceUnchanged", False),
            ("sourceSha256", "notasha"),
        ]:
            doc=fixture(5*gate.GIB)
            doc[change[0]]=change[1]
            with self.subTest(change=change),self.assertRaises(gate.layout.Refused):
                gate.assess(doc, 16)
        contradictory=fixture(5*gate.GIB)
        contradictory["files"].append(
            {"path":"sources/INSTALL2.SWM","bytes":100,"sha256":"b"*64})
        contradictory["listedFileCount"] += 1
        with self.assertRaises(gate.layout.Refused):
            gate.assess(contradictory,16)


if __name__ == "__main__":
    unittest.main()
