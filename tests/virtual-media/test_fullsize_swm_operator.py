"""Lightweight fail-closed policy for opt-in >4-GiB WIM staging."""
from pathlib import Path
import importlib.util
import tempfile
import unittest


path = Path(__file__).with_name("qualify-fullsize-swm-virtual.py")
spec = importlib.util.spec_from_file_location("fullsize_operator", path)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class FullsizeOperatorTests(unittest.TestCase):
    def test_source_size_scratch_budget_and_virtual_capacity(self):
        G = subject.GIB
        needed = subject.validate_scratch_budget(5*G, 19*G, 16)
        self.assertEqual(needed, 18*G)
        for size, free, capacity in (
            (4*G, 100*G, 16), (16*G+1, 100*G, 16),
            (5*G, 17*G, 16), (5*G, 100*G, 7),
            (5*G, 100*G, 25), (True, 100*G, 16),
        ):
            with self.subTest(size=size, free=free, capacity=capacity):
                with self.assertRaises(subject.Refused):
                    subject.validate_scratch_budget(size, free, capacity)

    def test_refuse_symlink_or_nonregular_source_and_scratch(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            source=root/"source.wim"
            source.write_bytes(b"not a real WIM")
            alias=root/"alias.wim"
            alias.symlink_to(source)
            self.assertEqual(subject.safe_regular(source),source.resolve())
            with self.assertRaises(subject.Refused):
                subject.safe_regular(alias)
            with self.assertRaises(subject.Refused):
                subject.safe_regular(root)
            directory=root/"aliasdir"
            directory.symlink_to(root, target_is_directory=True)
            with self.assertRaises(subject.Refused):
                subject.safe_directory(directory)

    def test_invalid_digest_refused_without_io_or_wimlib(self):
        with self.assertRaisesRegex(subject.Refused,"SHA-256"):
            subject.qualify(Path("/does-not-exist"),"bad",Path("/does-not-exist"))


if __name__ == "__main__":
    unittest.main()
