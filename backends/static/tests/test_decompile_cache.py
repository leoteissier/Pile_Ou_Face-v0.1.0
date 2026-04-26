# backends/static/tests/test_decompile_cache.py
import sys, os, tempfile, unittest, json
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile import (
    _cache_key, _read_cache, _write_cache, _stack_signature, decompile_function,
)


class TestCacheHelpers(unittest.TestCase):

    def test_cache_key_returns_16_hex_chars(self):
        key = _cache_key("/bin/ls", "0x401000")
        self.assertEqual(len(key), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in key))

    def test_cache_key_changes_with_addr(self):
        k1 = _cache_key("/bin/ls", "0x401000")
        k2 = _cache_key("/bin/ls", "0x401010")
        self.assertNotEqual(k1, k2)

    def test_cache_key_changes_with_path(self):
        k1 = _cache_key("/bin/ls", "0x401000")
        k2 = _cache_key("/bin/cat", "0x401000")
        self.assertNotEqual(k1, k2)

    def test_cache_key_changes_with_decompiler(self):
        k1 = _cache_key("/bin/ls", "0x401000", decompiler="r2pdc")
        k2 = _cache_key("/bin/ls", "0x401000", decompiler="ghidra")
        self.assertNotEqual(k1, k2)

    def test_cache_key_changes_with_quality(self):
        k1 = _cache_key("/bin/ls", "0x401000", quality="normal")
        k2 = _cache_key("/bin/ls", "0x401000", quality="max")
        self.assertNotEqual(k1, k2)

    def test_cache_key_changes_with_annotations_mtime(self):
        """La clé change quand le fichier annotations est modifié."""
        import time
        with tempfile.TemporaryDirectory() as d:
            ann_path = Path(d) / "ann.json"
            ann_path.write_text('{"0x401000": {"name": "foo"}}')
            k1 = _cache_key("/bin/ls", "0x401000", annotations_json=str(ann_path))
            # Simulate annotation edit — rewrite file (changes mtime)
            time.sleep(0.01)
            ann_path.write_text('{"0x401000": {"name": "bar"}}')
            k2 = _cache_key("/bin/ls", "0x401000", annotations_json=str(ann_path))
            self.assertNotEqual(k1, k2)

    def test_cache_key_reuses_identical_binary_content_across_paths(self):
        with tempfile.TemporaryDirectory() as d:
            a = Path(d) / "a.bin"
            b = Path(d) / "b.bin"
            payload = b"\x7fELF" + b"A" * 64
            a.write_bytes(payload)
            b.write_bytes(payload)
            k1 = _cache_key(str(a), "0x401000")
            k2 = _cache_key(str(b), "0x401000")
            self.assertEqual(k1, k2)

    def test_read_cache_returns_none_if_missing(self):
        with tempfile.TemporaryDirectory() as d:
            result = _read_cache("deadbeefcafe1234", Path(d))
            self.assertIsNone(result)

    def test_write_then_read_cache(self):
        with tempfile.TemporaryDirectory() as d:
            data = {"addr": "0x401000", "code": "int f() {}", "error": None}
            _write_cache("deadbeefcafe1234", Path(d), data)
            result = _read_cache("deadbeefcafe1234", Path(d))
            self.assertEqual(result, data)

    def test_write_cache_creates_dir(self):
        with tempfile.TemporaryDirectory() as d:
            subdir = Path(d) / "nested" / "cache"
            _write_cache("deadbeefcafe1234", subdir, {"x": 1})
            self.assertTrue((subdir / "deadbeefcafe1234.json").exists())


class TestDecompileFunctionCache(unittest.TestCase):

    def test_cache_hit_skips_decompiler(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}
            cached = {"addr": "0x401000", "code": "/* cached */", "error": None, "decompiler": "r2pdc"}
            key = _cache_key(
                "/bin/ls",
                "0x401000",
                stack_signature=_stack_signature(empty_stack, None),
                typed_structs_signature="",
            )
            _write_cache(key, cache_dir, cached)

            call_count = {"n": 0}
            def fake_r2(bp, addr):
                call_count["n"] += 1
                return {"addr": addr, "code": "/* live */", "error": None, "decompiler": "r2pdc"}

            with mock.patch("backends.static.decompile.decompile_function_r2", fake_r2), \
                 mock.patch("backends.static.decompile._is_r2_available", return_value=True), \
                 mock.patch("backends.static.decompile._is_r2ghidra_available", return_value=False), \
                 mock.patch("backends.static.decompile._is_ghidra_available", return_value=False), \
                 mock.patch("backends.static.decompile.typed_struct_signature", return_value=""), \
                 mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack):
                result = decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            self.assertEqual(call_count["n"], 0)
            self.assertEqual(result["code"], "/* cached */")

    def test_precision_mode_starts_with_retdec_in_compare_chain(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}
            calls = []

            def fake_retdec(bp, addr, func_name=""):
                calls.append("retdec")
                return {"addr": addr, "code": "int retdec_f() { return 0; }", "error": None, "decompiler": "retdec"}

            def fake_ghidra(bp, addr, func_name=""):
                calls.append("ghidra")
                return {"addr": addr, "code": "int ghidra_f() {}", "error": None, "decompiler": "ghidra"}

            def fake_angr(bp, addr):
                calls.append("angr")
                return {"addr": addr, "code": "int angr_f() {}", "error": None, "decompiler": "angr"}

            with mock.patch("backends.static.decompile.decompile_function_retdec", fake_retdec), \
                 mock.patch("backends.static.decompile.decompile_function_ghidra", fake_ghidra), \
                 mock.patch("backends.static.decompile.decompile_function_angr", fake_angr), \
                 mock.patch("backends.static.decompile._is_ghidra_available", return_value=True), \
                 mock.patch("backends.static.decompile._is_retdec_available", return_value=True), \
                 mock.patch("backends.static.decompile._is_angr_available", return_value=True), \
                 mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack):
                result = decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir, quality="precision")

            self.assertEqual(calls[0], "retdec")
            self.assertEqual(result.get("decompiler"), "retdec")
            self.assertEqual(result.get("quality"), "precision")

    def test_precision_mode_compares_backends_and_keeps_best_scored_output(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}
            calls = []

            def fake_ghidra(bp, addr, func_name=""):
                calls.append("ghidra")
                return {
                    "addr": addr,
                    "code": "int ghidra_f() {\n  local_10 = 0;\n  return local_10;\n}",
                    "error": None,
                    "decompiler": "ghidra",
                }

            def fake_retdec(bp, addr, func_name=""):
                calls.append("retdec")
                return {
                    "addr": addr,
                    "code": (
                        "int parse_cfg(int argc, char **argv) {\n"
                        "    helper(argv[1]);\n"
                        "    return 1;\n"
                        "}\n"
                    ),
                    "error": None,
                    "decompiler": "retdec",
                }

            def fake_angr(bp, addr):
                calls.append("angr")
                return {
                    "addr": addr,
                    "code": "int parse_cfg(void) { return 0; }",
                    "error": None,
                    "decompiler": "angr",
                }

            with mock.patch("backends.static.decompile.decompile_function_ghidra", fake_ghidra), \
                 mock.patch("backends.static.decompile.decompile_function_retdec", fake_retdec), \
                 mock.patch("backends.static.decompile.decompile_function_angr", fake_angr), \
                 mock.patch("backends.static.decompile._is_ghidra_available", return_value=True), \
                 mock.patch("backends.static.decompile._is_retdec_available", return_value=True), \
                 mock.patch("backends.static.decompile._is_angr_available", return_value=True), \
                 mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack):
                result = decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir, quality="precision")

            self.assertEqual(calls, ["retdec", "ghidra", "angr"])
            self.assertEqual(result.get("decompiler"), "retdec")
            self.assertEqual(result.get("quality_details", {}).get("strategy"), "compare_backends")
            self.assertEqual(len(result.get("quality_details", {}).get("backends", [])), 3)

    def test_decompile_binary_precision_compares_backends(self):
        calls = []

        def fake_ghidra(bp):
            calls.append("ghidra")
            return {
                "functions": [{"addr": "0x401000", "code": "int f() { return 0; }", "error": None}],
                "error": None,
                "decompiler": "ghidra",
            }

        def fake_retdec(bp):
            calls.append("retdec")
            return {
                "functions": [
                    {"addr": "0x401000", "code": "int f() { helper(); return 0; }", "error": None},
                    {"addr": "0x401020", "code": "int helper() { return 1; }", "error": None},
                    {"addr": "0x401040", "code": "int tail() { return helper(); }", "error": None},
                ],
                "error": None,
                "decompiler": "retdec",
            }

        def fake_angr(bp):
            calls.append("angr")
            return {
                "functions": [{"addr": "0x401000", "code": "int f() { return 0; }", "error": None}],
                "error": None,
                "decompiler": "angr",
            }

        from backends.static.decompile import decompile_binary

        with mock.patch("backends.static.decompile.decompile_binary_ghidra", fake_ghidra), \
             mock.patch("backends.static.decompile.decompile_binary_retdec", fake_retdec), \
             mock.patch("backends.static.decompile.decompile_binary_angr", fake_angr), \
             mock.patch("backends.static.decompile._is_ghidra_available", return_value=True), \
             mock.patch("backends.static.decompile._is_retdec_available", return_value=True), \
             mock.patch("backends.static.decompile._is_angr_available", return_value=True):
            result = decompile_binary("/bin/ls", quality="precision")

        self.assertEqual(calls, ["retdec", "ghidra", "angr"])
        self.assertEqual(result.get("decompiler"), "retdec")
        self.assertEqual(result.get("quality_details", {}).get("strategy"), "compare_backends")

    def test_quality_max_alias_uses_precision_mode(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}
            calls = []

            def fake_retdec(bp, addr, func_name=""):
                calls.append("retdec")
                return {"addr": addr, "code": "int f() { return 0; }", "error": None, "decompiler": "retdec"}

            with mock.patch("backends.static.decompile.decompile_function_retdec", fake_retdec), \
                 mock.patch("backends.static.decompile._is_ghidra_available", return_value=False), \
                 mock.patch("backends.static.decompile._is_retdec_available", return_value=True), \
                 mock.patch("backends.static.decompile._is_angr_available", return_value=False), \
                 mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack):
                result = decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir, quality="max")

            self.assertEqual(calls, ["retdec"])
            self.assertEqual(result.get("quality"), "precision")

    def test_cache_miss_writes_cache(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}

            with mock.patch("backends.static.decompile.decompile_function_ghidra",
                            return_value={"addr": "0x401000", "code": "int f(){}", "error": None, "decompiler": "ghidra"}), \
                 mock.patch("backends.static.decompile._is_ghidra_available", return_value=True), \
                 mock.patch("backends.static.decompile._is_retdec_available", return_value=False), \
                 mock.patch("backends.static.decompile._is_angr_available", return_value=False), \
                 mock.patch("backends.static.decompile.typed_struct_signature", return_value=""), \
                 mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack):
                decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            key = _cache_key(
                "/bin/ls",
                "0x401000",
                stack_signature=_stack_signature(empty_stack, None),
                typed_structs_signature="",
            )
            cached = _read_cache(key, cache_dir)
            assert cached is not None
            self.assertEqual(cached["code"], "int f(){}")

    def test_error_result_not_cached(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}

            with mock.patch("backends.static.decompile._is_r2ghidra_available", return_value=False), \
                 mock.patch("backends.static.decompile._is_r2_available", return_value=False), \
                 mock.patch("backends.static.decompile._is_ghidra_available", return_value=False), \
                 mock.patch("backends.static.decompile._is_retdec_available", return_value=False), \
                 mock.patch("backends.static.decompile._is_angr_available", return_value=False), \
                 mock.patch("backends.static.decompile.typed_struct_signature", return_value=""), \
                 mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack):
                decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            key = _cache_key(
                "/bin/ls",
                "0x401000",
                stack_signature=_stack_signature(empty_stack, None),
                typed_structs_signature="",
            )
            self.assertIsNone(_read_cache(key, cache_dir))


class TestCLICacheDir(unittest.TestCase):

    def test_cache_dir_arg_accepted(self):
        """--cache-dir est reconnu sans lever d'erreur argparse."""
        import subprocess, sys
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run(
                [sys.executable, "backends/static/decompile.py",
                 "--binary", "/nonexistent", "--addr", "0x401000",
                 "--cache-dir", d,
                 "--quality", "max"],
                capture_output=True, text=True,
                cwd=str(ROOT),
            )
            # Expect a JSON error about missing file, not an argparse error
            self.assertNotIn("unrecognized arguments", result.stderr)
            self.assertNotIn("error: unrecognized", result.stderr)
            # Output should be valid JSON with an error field
            if result.stdout.strip():
                out = json.loads(result.stdout)
                self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
