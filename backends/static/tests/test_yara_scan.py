"""Tests pour backends.static.yara_scan."""

import platform
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.yara_scan import scan_with_yara


class TestYaraScan(unittest.TestCase):
    """Tests de scan_with_yara."""

    def test_nonexistent_binary_returns_error(self):
        results, error = scan_with_yara("/nonexistent", "/tmp")
        self.assertEqual(results, [])
        self.assertIsNotNone(error)

    def test_nonexistent_rules_returns_error(self):
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            path = f.name
        try:
            results, error = scan_with_yara(path, "/nonexistent_rules")
            self.assertEqual(results, [])
            self.assertIsNotNone(error)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_scan_uses_custom_rules_when_no_rules_path(self):
        """Si rules_path est None, les règles custom du projet sont utilisées."""
        tmpdir = tempfile.mkdtemp()
        try:
            from backends.static.rules_manager import RulesManager

            mgr = RulesManager(tmpdir)
            mgr.add_user_rule(
                "never_match.yar",
                "rule NeverMatch { condition: false }",
                "yara",
            )
            binary = (
                "/dev/null" if platform.system() != "Windows" else tmpdir + "/empty.bin"
            )
            if platform.system() == "Windows":
                open(binary, "wb").close()
            results, error = scan_with_yara(binary, project_root=tmpdir)
            # L'important : pas d'erreur "aucune règle définie"
            if error:
                self.assertNotIn("Aucune règle YARA définie", error)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
