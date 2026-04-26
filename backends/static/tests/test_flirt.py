import sys, unittest, tempfile, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.flirt import match_signatures, _match_pattern, _load_sigs


class TestFlirt(unittest.TestCase):

    def test_nonexistent_returns_empty(self):
        r = match_signatures("/nonexistent")
        self.assertEqual(r, [])

    def test_result_fields(self):
        data = bytes([0x55, 0x48, 0x89, 0xE5, 0x48, 0x85, 0xFF, 0x00] * 4)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(data)
            path = f.name
        try:
            r = match_signatures(path)
            for entry in r:
                for field in ("addr", "name", "lib", "confidence"):
                    self.assertIn(field, entry)
        finally:
            os.unlink(path)

    def test_pattern_match_exact(self):
        data = bytes([0x55, 0x48, 0x89, 0xE5])
        self.assertTrue(_match_pattern(data, 0, [0x55, 0x48, 0x89, 0xE5]))

    def test_pattern_match_wildcard(self):
        data = bytes([0x55, 0x48, 0xFF, 0xE5])
        self.assertTrue(_match_pattern(data, 0, [0x55, 0x48, None, 0xE5]))

    def test_pattern_no_match(self):
        data = bytes([0x00, 0x00, 0x00, 0x00])
        self.assertFalse(_match_pattern(data, 0, [0x55, 0x48, 0x89, 0xE5]))

    def test_load_sigs_returns_list(self):
        sigs = _load_sigs()
        self.assertIsInstance(sigs, list)
        self.assertGreater(len(sigs), 0)


if __name__ == "__main__":
    unittest.main()
