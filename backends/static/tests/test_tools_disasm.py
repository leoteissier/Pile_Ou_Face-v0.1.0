"""Tests pour tools.static.disasm (CLI désassemblage)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.tests.util import compile_minimal_elf
from backends.static.disasm import main


class TestDisasmMain(unittest.TestCase):
    """Tests du CLI désassemblage."""

    def test_nonexistent_binary_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_asm = Path(tmp) / "out.asm"
            old_argv = sys.argv
            try:
                sys.argv = [
                    "disasm",
                    "--binary",
                    str(Path(tmp) / "nonexistent.elf"),
                    "--output",
                    str(out_asm),
                ]
                result = main()
            finally:
                sys.argv = old_argv
            self.assertNotEqual(result, 0)

    def test_real_binary(self):
        """Compile un binaire minimal, désassemble via CLI, supprime à la fin."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")
            out_asm = tmp_path / "out.asm"
            out_map = tmp_path / "out.json"
            old_argv = sys.argv
            try:
                sys.argv = [
                    "disasm",
                    "--binary",
                    str(binary),
                    "--output",
                    str(out_asm),
                    "--output-mapping",
                    str(out_map),
                ]
                result = main()
            finally:
                sys.argv = old_argv
            self.assertEqual(result, 0)
            self.assertTrue(out_asm.exists())
            self.assertTrue(out_map.exists())


if __name__ == "__main__":
    unittest.main()
