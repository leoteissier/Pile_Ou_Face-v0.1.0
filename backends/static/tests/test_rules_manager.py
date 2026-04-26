"""Tests pour backends.static.rules_manager."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.rules_manager import RulesManager


class TestRulesManager(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _mgr(self, global_cfg=None):
        return RulesManager(self.tmpdir, global_cfg)

    def test_list_empty_when_no_rules_dir(self):
        self.assertEqual(self._mgr().list_rules(), [])

    def test_add_yara_rule_creates_file(self):
        rule_id = self._mgr().add_user_rule(
            "test.yar", "rule Foo { condition: false }", "yara"
        )
        self.assertEqual(rule_id, "user:yara:test.yar")
        f = Path(self.tmpdir) / ".pile-ou-face" / "rules" / "yara" / "test.yar"
        self.assertTrue(f.exists())

    def test_add_capa_rule_creates_file(self):
        rule_id = self._mgr().add_user_rule("my.yml", "name: x", "capa")
        self.assertEqual(rule_id, "user:capa:my.yml")
        f = Path(self.tmpdir) / ".pile-ou-face" / "rules" / "capa" / "my.yml"
        self.assertTrue(f.exists())

    def test_list_returns_added_rule_enabled_by_default(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        rules = mgr.list_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "user:yara:test.yar")
        self.assertTrue(rules[0]["enabled"])

    def test_toggle_disables_rule(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        mgr.toggle_rule("user:yara:test.yar", False)
        self.assertFalse(mgr.list_rules()[0]["enabled"])

    def test_toggle_re_enables_rule(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        mgr.toggle_rule("user:yara:test.yar", False)
        mgr.toggle_rule("user:yara:test.yar", True)
        self.assertTrue(mgr.list_rules()[0]["enabled"])

    def test_delete_user_rule(self):
        mgr = self._mgr()
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        mgr.delete_user_rule("user:yara:test.yar")
        self.assertEqual(mgr.list_rules(), [])

    def test_delete_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            self._mgr().delete_user_rule("user:yara:ghost.yar")

    def test_get_active_yara_paths_only_enabled(self):
        mgr = self._mgr()
        mgr.add_user_rule("a.yar", "rule A { condition: false }", "yara")
        mgr.add_user_rule("b.yar", "rule B { condition: false }", "yara")
        mgr.toggle_rule("user:yara:b.yar", False)
        paths = mgr.get_active_yara_paths()
        self.assertEqual(len(paths), 1)
        self.assertTrue(str(paths[0]).endswith("a.yar"))

    def test_get_active_yara_paths_with_extra(self):
        mgr = self._mgr()
        mgr.add_user_rule("a.yar", "rule A { condition: false }", "yara")
        extra = Path(self.tmpdir) / "extra.yar"
        extra.write_text("rule Extra { condition: false }", encoding="utf-8")
        paths = mgr.get_active_yara_paths(extra_path=extra)
        self.assertEqual(len(paths), 2)

    def test_inject_capa_only_active(self):
        mgr = self._mgr()
        mgr.add_user_rule("active.yml", "name: active", "capa")
        mgr.add_user_rule("inactive.yml", "name: inactive", "capa")
        mgr.toggle_rule("user:capa:inactive.yml", False)
        capa_dir = Path(self.tmpdir) / "capa-rules"
        capa_dir.mkdir()
        mgr.inject_active_capa_rules(capa_dir)
        injected = list((capa_dir / "custom").iterdir())
        self.assertEqual(len(injected), 1)
        self.assertEqual(injected[0].name, "active.yml")

    def test_global_config_default_overridden_by_project(self):
        global_cfg = Path(self.tmpdir) / "global.json"
        global_cfg.write_text(
            json.dumps(
                {"version": 1, "rules": {"user:yara:test.yar": {"enabled": False}}}
            ),
            encoding="utf-8",
        )
        mgr = self._mgr(str(global_cfg))
        mgr.add_user_rule("test.yar", "rule Foo { condition: false }", "yara")
        # Global dit disabled
        self.assertFalse(mgr.list_rules()[0]["enabled"])
        # Override projet le réactive
        mgr.toggle_rule("user:yara:test.yar", True)
        self.assertTrue(mgr.list_rules()[0]["enabled"])

    def test_add_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            self._mgr().add_user_rule("bad.txt", "content", "invalid")


if __name__ == "__main__":
    unittest.main()
