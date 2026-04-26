# backends/static/tests/test_func_similarity.py
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static import func_similarity


class TestFuncSimilarityDb(unittest.TestCase):

    def _write_binary(self, directory: str, name: str, content: bytes) -> str:
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def test_index_and_list_reference_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            ref = self._write_binary(tmp, "ref.bin", b"\x90" * 32)
            fake_index = [{"addr": "0x1000", "name": "puts", "sig": [1, 2, 3], "opcode_count": 6}]
            with mock.patch("backends.static.func_similarity.index_binary", return_value=fake_index):
                result = func_similarity.index_reference_binary(ref, label="libc-demo", workspace_root=tmp)
            self.assertIsNone(result.get("error"))
            self.assertEqual(result["stats"]["workspace_binaries"], 1)
            self.assertEqual(result["references"][0]["label"], "libc-demo")

    def test_compare_against_reference_db_uses_indexed_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self._write_binary(tmp, "target.bin", b"A" * 32)
            ref = self._write_binary(tmp, "ref.bin", b"B" * 32)
            ref_index = [{"addr": "0x2000", "name": "printf", "sig": [7, 7, 7], "opcode_count": 8}]
            target_index = [{"addr": "0x1000", "name": "sub_1000", "sig": [7, 7, 7], "opcode_count": 8}]
            with mock.patch("backends.static.func_similarity.index_binary", side_effect=[ref_index, target_index]):
                func_similarity.index_reference_binary(ref, label="libc-demo", workspace_root=tmp)
                result = func_similarity.compare_against_reference_db(target, threshold=0.4, top=1, workspace_root=tmp)
            self.assertIsNone(result.get("error"))
            self.assertEqual(result["stats"]["workspace_binaries"], 1)
            self.assertEqual(len(result["matches"]), 1)
            self.assertEqual(result["matches"][0]["ref_label"], "libc-demo")

    def test_clear_reference_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = func_similarity.get_reference_db_path(tmp)
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            with open(db_path, "w", encoding="utf-8") as handle:
                handle.write('{"references":[{"name":"x"}]}')
            result = func_similarity.clear_reference_db(tmp)
            self.assertEqual(result["stats"]["workspace_binaries"], 0)
            self.assertEqual(func_similarity.load_reference_db(tmp)["references"], [])

    def test_update_reference_label_changes_only_workspace_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_payload = {
                "references": [
                    {
                        "sha256": "abc123",
                        "label": "openssl-old",
                        "name": "libssl.so",
                        "functions": [{"addr": "0x1", "name": "SSL_read", "sig": [1, 2, 3], "opcode_count": 6}],
                    }
                ]
            }
            func_similarity.save_reference_db(db_payload, tmp)
            result = func_similarity.update_reference_label("abc123", "openssl-prod", tmp)
            self.assertIsNone(result.get("error"))
            self.assertEqual(result["updated"]["label"], "openssl-prod")
            self.assertEqual(result["references"][0]["label"], "openssl-prod")
            self.assertTrue(result["references"][0]["editable"])

    def test_remove_reference_entry_deletes_only_requested_workspace_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_payload = {
                "references": [
                    {"sha256": "abc123", "label": "one", "name": "one.bin", "functions": [{"addr": "0x1", "name": "f1", "sig": [1], "opcode_count": 4}]},
                    {"sha256": "def456", "label": "two", "name": "two.bin", "functions": [{"addr": "0x2", "name": "f2", "sig": [2], "opcode_count": 4}]},
                ]
            }
            func_similarity.save_reference_db(db_payload, tmp)
            result = func_similarity.remove_reference_entry("abc123", tmp)
            self.assertIsNone(result.get("error"))
            self.assertEqual(result["stats"]["workspace_binaries"], 1)
            self.assertEqual(result["references"][0]["label"], "two")
            self.assertEqual(result["removed"]["id"], "abc123")

    def test_list_reference_db_includes_bundled_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled_path = Path(tmp) / "bundled.json"
            bundled_path.write_text(
                '{"pack":{"name":"starter-pack"},"references":[{"label":"openssl-starter","name":"libssl","function_count":2,"functions":[{"addr":"0x1","name":"_SSL_read","sig":[1,2,3],"opcode_count":8},{"addr":"0x2","name":"_SSL_write","sig":[3,2,1],"opcode_count":8}]}]}',
                encoding="utf-8",
            )
            with mock.patch("backends.static.func_similarity.BUNDLED_DB_PATH", bundled_path):
                result = func_similarity.list_reference_db(tmp)
            self.assertIsNone(result.get("error"))
            self.assertEqual(result["stats"]["bundled_binaries"], 1)
            self.assertEqual(result["references"][0]["source"], "bundled")
            self.assertEqual(result["references"][0]["pack"], "starter-pack")
            self.assertFalse(result["references"][0]["editable"])

    def test_compare_against_reference_db_uses_bundled_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self._write_binary(tmp, "target.bin", b"A" * 32)
            bundled_path = Path(tmp) / "bundled.json"
            bundled_path.write_text(
                '{"pack":{"name":"starter-pack"},"references":[{"label":"openssl-starter","name":"libssl","family":"openssl","function_count":1,"functions":[{"addr":"0x2000","name":"_SSL_read","sig":[7,7,7],"opcode_count":8}]}]}',
                encoding="utf-8",
            )
            target_index = [{"addr": "0x1000", "name": "sub_1000", "sig": [7, 7, 7], "opcode_count": 8}]
            with mock.patch("backends.static.func_similarity.BUNDLED_DB_PATH", bundled_path), \
                 mock.patch("backends.static.func_similarity.index_binary", return_value=target_index):
                result = func_similarity.compare_against_reference_db(target, threshold=0.4, top=1, workspace_root=tmp)
            self.assertIsNone(result.get("error"))
            self.assertEqual(result["stats"]["bundled_binaries"], 1)
            self.assertEqual(result["matches"][0]["ref_source"], "bundled")
            self.assertEqual(result["matches"][0]["ref_label"], "openssl-starter")

    def test_load_disasm_falls_back_when_default_cache_path_fails(self):
        fake_lines = [{"addr": "0x1000", "text": "ret"}]
        with mock.patch("backends.static.cache.default_cache_path", side_effect=PermissionError("nope")), \
             mock.patch("backends.static.disasm.disassemble_with_capstone", return_value=fake_lines):
            result = func_similarity._load_disasm("/bin/ls")
        self.assertEqual(result, fake_lines)


if __name__ == "__main__":
    unittest.main()
