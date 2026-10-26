"""Does not generate large fixture: validates expensive test admission only."""
from pathlib import Path
import importlib.util
import unittest

path = Path(__file__).with_name("qualify-generated-4gib-swm.py")
spec = importlib.util.spec_from_file_location("generated_swm", path)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class SyntheticGenerationPolicyTest(unittest.TestCase):
    def test_plan_exceeds_four_gib_with_bounded_nonidentical_sources(self):
        items = stage.file_plan(4352)
        self.assertEqual(len(items), 17)
        self.assertEqual(sum(items), 4352)
        self.assertTrue(all(size <= 256 for size in items))

    def test_requires_a_realistic_disk_budget(self):
        expected = 4 * 4352 * stage.MIB + 6 * stage.GIB
        self.assertEqual(stage.scratch_requirement(4352 * stage.MIB), expected)
        self.assertGreater(expected, 20 * stage.GIB)

    def test_refuses_small_or_oversized_proposals(self):
        for value in (0, 4096, 6145, -1, True, 1.0):
            with self.subTest(value=value):
                with self.assertRaises(stage.qualifier.Refused):
                    stage.file_plan(value)


if __name__ == "__main__":
    unittest.main()
