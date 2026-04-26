# backends/static/tests/test_exception_handlers.py
import os
import sys
import json
import subprocess
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)
from backends.static.tests.fixtures.make_elf import make_minimal_elf

try:
    import lief as _lief
    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


def run_eh(binary):
    r = subprocess.run(
        [sys.executable, "backends/static/exception_handlers.py", "--binary", binary],
        capture_output=True, text=True, cwd=ROOT,
    )
    return json.loads(r.stdout)


class TestExceptionHandlers(unittest.TestCase):

    def test_error_on_missing(self):
        result = run_eh("/nonexistent/binary")
        self.assertIsNotNone(result.get("error"))

    def test_output_shape_on_elf(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_eh(elf)
            self.assertIn("format", result)
            self.assertIn("entries", result)
            self.assertIn("count", result)
            self.assertIsInstance(result["entries"], list)

    def test_each_entry_has_required_fields(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_eh(elf)
            for entry in result.get("entries", []):
                self.assertIn("handler_type", entry)
                self.assertIn("func_start", entry)

    def test_elf_format_reported(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_eh(elf)
            self.assertEqual(result.get("format"), "ELF")

    def test_shape_on_direct_call(self):
        from backends.static.exception_handlers import get_exception_handlers
        self.assertTrue(callable(get_exception_handlers))
        result = get_exception_handlers("/nonexistent/binary")
        self.assertIsInstance(result, dict)
        self.assertIn("format", result)
        self.assertIn("arch", result)
        self.assertIn("entries", result)
        self.assertIn("count", result)


if __name__ == "__main__":
    unittest.main()
