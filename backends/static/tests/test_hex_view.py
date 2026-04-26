"""Tests pour backends.static.hex_view."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _import_make_elf():
    p = Path(__file__).parent / "fixtures" / "make_elf.py"
    spec = importlib.util.spec_from_file_location("make_elf", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_minimal_elf


make_minimal_elf = _import_make_elf()


def run(args):
    """Run hex_view.py as a subprocess and return parsed JSON output."""
    r = subprocess.run(
        [sys.executable, "backends/static/hex_view.py"] + args,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(f"hex_view.py failed:\n{r.stderr}")
    return json.loads(r.stdout)


class TestHexView(unittest.TestCase):
    """Tests du dump hexadécimal de hex_view.py."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.binary = str(Path(self.tmp) / "test.elf")
        make_minimal_elf(self.binary)

    def test_basic_dump(self):
        """Vérifie la structure de base des lignes de dump."""
        data = run(["--binary", self.binary, "--offset", "0", "--length", "64"])
        self.assertIn("rows", data)
        self.assertGreater(len(data["rows"]), 0)
        row = data["rows"][0]
        self.assertIn("offset", row)
        self.assertIn("hex", row)
        self.assertIn("ascii", row)
        self.assertEqual(len(row["hex"].split()), 16)

    def test_ascii_column(self):
        """Vérifie que la colonne ascii contient des caractères valides."""
        data = run(["--binary", self.binary, "--offset", "0", "--length", "16"])
        self.assertGreater(len(data["rows"]), 0)
        row = data["rows"][0]
        self.assertTrue("." in row["ascii"] or row["ascii"].isprintable())

    def test_sections(self):
        """Vérifie que la liste de sections est présente et bien formée."""
        data = run(["--binary", self.binary, "--offset", "0", "--length", "16"])
        self.assertIn("sections", data)
        self.assertIsInstance(data["sections"], list)

    def test_out_of_range(self):
        """Un offset hors limites doit retourner une liste de lignes vide."""
        data = run(["--binary", self.binary, "--offset", "99999999", "--length", "16"])
        self.assertEqual(data["rows"], [])


if __name__ == "__main__":
    unittest.main()
