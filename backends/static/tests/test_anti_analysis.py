import sys, unittest, tempfile, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.anti_analysis import (
    detect_anti_analysis,
    _check_timing,
    _check_vm_strings,
)


class TestAntiAnalysis(unittest.TestCase):

    def test_nonexistent_returns_empty(self):
        r = detect_anti_analysis("/nonexistent")
        self.assertEqual(r, [])

    def test_result_is_list(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 128)
            path = f.name
        try:
            r = detect_anti_analysis(path)
            self.assertIsInstance(r, list)
        finally:
            os.unlink(path)

    def test_entry_has_required_fields(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"vmware" + b"\x00" * 128)
            path = f.name
        try:
            r = detect_anti_analysis(path)
            for entry in r:
                for field in ("technique", "description", "bypass", "confidence"):
                    self.assertIn(field, entry)
        finally:
            os.unlink(path)

    def test_vmware_string_detected(self):
        data = b"checking vmware environment"
        results = _check_vm_strings(data)
        self.assertTrue(any("vmware" in r["description"].lower() for r in results))

    def test_vbox_string_detected(self):
        data = b"VirtualBox detected"
        results = _check_vm_strings(data)
        self.assertGreater(len(results), 0)

    def test_rdtsc_sequence_detected(self):
        data = b"\x0f\x31\x0f\xa2\x0f\x31"
        results = _check_timing(data)
        self.assertGreater(len(results), 0)

    def test_clean_binary_has_no_detections(self):
        data = b"\x90" * 64
        self.assertEqual(_check_vm_strings(data), [])
        self.assertEqual(_check_timing(data), [])


if __name__ == "__main__":
    unittest.main()
