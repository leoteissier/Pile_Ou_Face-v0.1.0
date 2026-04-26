"""Tests pour backends.static.capa_scan."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.capa_scan import scan_with_capa


class TestCapaScan(unittest.TestCase):
    """Tests de scan_with_capa."""

    def test_nonexistent_binary_returns_error(self):
        result = scan_with_capa("/nonexistent/binary")
        self.assertIn("error", result)
        self.assertIn("capabilities", result)
        self.assertIsInstance(result["capabilities"], list)

    def test_inject_custom_capa_rules_via_scan(self):
        """inject_active_capa_rules est appelé sans erreur avec un projet valide."""
        tmpdir = tempfile.mkdtemp()
        try:
            from backends.static.rules_manager import RulesManager

            mgr = RulesManager(tmpdir)
            mgr.add_user_rule("custom.yml", "name: custom", "capa")
            capa_dir = Path(tmpdir) / "capa-rules"
            capa_dir.mkdir()
            mgr.inject_active_capa_rules(capa_dir)
            self.assertTrue((capa_dir / "custom" / "custom.yml").exists())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
