# backends/static/tests/test_decompile.py
import sys, os, tempfile, unittest, json, subprocess
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile import (
    _get_decompiler_docker_image,
    _docker_missing_image_error,
    _preferred_docker_platform_for_decompiler,
    _resolve_function_target,
    list_available_decompilers,
    decompile_function,
    decompile_binary,
    _is_retdec_available,
    _load_custom_decompilers,
    _normalize_quality,
    _parse_c_like_function_blocks,
    _run_builtin_decompiler_in_docker,
    _run_custom_decompiler,
    _score_decompile_code,
)


class TestDecompile(unittest.TestCase):

    def test_retdec_availability_returns_bool(self):
        result = _is_retdec_available()
        self.assertIsInstance(result, bool)

    def test_nonexistent_file_returns_error(self):
        r = decompile_function("/nonexistent/binary", "0x401000")
        self.assertIn("error", r)
        self.assertIsNotNone(r["error"])

    def test_result_has_required_fields(self):
        r = decompile_function("/nonexistent/binary", "0x401000")
        for field in ("addr", "code", "error"):
            self.assertIn(field, r)

    def test_binary_result_has_required_fields(self):
        r = decompile_binary("/nonexistent/binary")
        for field in ("functions", "error"):
            self.assertIn(field, r)

    def test_no_retdec_returns_helpful_error(self):
        import unittest.mock as mock

        # Use an existing file so the file-existence guard passes and we reach
        # the retdec-availability guard.
        with mock.patch(
            "backends.static.decompile._find_retdec_executable", return_value=None
        ):
            with tempfile.TemporaryDirectory() as d:
                r = decompile_function(
                    "/bin/ls",
                    "0x401000",
                    decompiler="retdec",
                    provider="local",
                    cache_dir=Path(d),
                )
                self.assertIn("retdec", r.get("error", "").lower())

    def test_parse_retdec_c_output_splits_functions(self):
        from backends.static.decompile import _parse_retdec_output

        sample = "// Address range: 0x401000 - 0x401050\nint f1() { return 0; }\n// Address range: 0x401060 - 0x4010a0\nint f2() { }\n"
        fns = _parse_retdec_output(sample)
        self.assertEqual(len(fns), 2)
        self.assertEqual(fns[0]["addr"], "0x401000")
        self.assertIn("f1", fns[0]["code"])
        self.assertNotIn("0x401050", fns[0]["code"])

    def test_parse_empty_output(self):
        from backends.static.decompile import _parse_retdec_output

        self.assertEqual(_parse_retdec_output(""), [])

    def test_builtin_docker_image_defaults_to_per_backend_image(self):
        self.assertEqual(
            _get_decompiler_docker_image("retdec"),
            "pile-ou-face/decompiler-retdec:latest",
        )

    def test_missing_builtin_docker_image_error_suggests_make(self):
        error = _docker_missing_image_error("retdec", "pile-ou-face/decompiler-retdec:latest")
        self.assertIn("make decompiler-docker-build DECOMPILER=retdec", error)
        self.assertIn("POF_DECOMPILER_IMAGE_RETDEC", error)

    def test_builtin_docker_run_reports_missing_image_helpfully(self):
        missing_stderr = (
            "Unable to find image 'pile-ou-face/decompiler-retdec:latest' locally\n"
            "docker: Error response from daemon: pull access denied for pile-ou-face/decompiler-retdec, "
            "repository does not exist or may require 'docker login': denied: requested access to the resource is denied"
        )
        completed = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=125,
            stdout="",
            stderr=missing_stderr,
        )
        with mock.patch("backends.static.decompile._is_docker_decompiler_image_available", return_value=True), \
             mock.patch("backends.static.decompile.subprocess.run", return_value=completed):
            result = _run_builtin_decompiler_in_docker("retdec", "/bin/ls", addr="0x401000")
        self.assertIn("make decompiler-docker-build DECOMPILER=retdec", result.get("error", ""))
        self.assertEqual(result.get("docker_image"), "pile-ou-face/decompiler-retdec:latest")

    def test_builtin_docker_run_uses_real_container_result_even_if_probe_is_unreliable(self):
        completed = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout=json.dumps({
                "addr": "0x401000",
                "code": "int add(){ return 5; }",
                "error": None,
            }),
            stderr="",
        )
        with mock.patch(
            "backends.static.decompile._is_docker_decompiler_image_available",
            side_effect=AssertionError("preflight inspect should not gate docker run"),
        ), mock.patch("backends.static.decompile.subprocess.run", return_value=completed):
            result = _run_builtin_decompiler_in_docker("retdec", "/bin/ls", addr="0x401000")
        self.assertIsNone(result.get("error"))
        self.assertEqual(result.get("provider"), "docker")
        self.assertEqual(result.get("docker_image"), "pile-ou-face/decompiler-retdec:latest")
        self.assertIn("return 5", result.get("code", ""))

    def test_docker_image_availability_rechecks_stale_negative_cache(self):
        image = "pile-ou-face/decompiler-retdec:latest"
        from backends.static import decompile as decompile_mod

        original_cache = dict(decompile_mod._DOCKER_AVAILABLE_CACHE)
        decompile_mod._DOCKER_AVAILABLE_CACHE.clear()
        decompile_mod._DOCKER_AVAILABLE_CACHE[image] = False
        try:
            completed = subprocess.CompletedProcess(
                args=["docker", "image", "inspect", image],
                returncode=0,
                stdout="[]",
                stderr="",
            )
            with mock.patch("backends.static.decompile._find_docker_executable", return_value="/usr/bin/docker"), \
                 mock.patch("backends.static.decompile.subprocess.run", return_value=completed) as run_mock:
                self.assertTrue(decompile_mod._is_docker_decompiler_image_available(image))
            run_mock.assert_called_once()
            self.assertTrue(decompile_mod._DOCKER_AVAILABLE_CACHE[image])
        finally:
            decompile_mod._DOCKER_AVAILABLE_CACHE.clear()
            decompile_mod._DOCKER_AVAILABLE_CACHE.update(original_cache)

    def test_preferred_docker_platform_is_only_forced_by_env(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            self.assertEqual(_preferred_docker_platform_for_decompiler("retdec"), "")
        with mock.patch.dict(os.environ, {"POF_DOCKER_PLATFORM": "linux/amd64"}, clear=False):
            self.assertEqual(_preferred_docker_platform_for_decompiler("retdec"), "linux/amd64")

    def test_explicit_angr_function_dispatch_does_not_fall_back_to_auto(self):
        empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}
        with tempfile.TemporaryDirectory() as d, \
             mock.patch(
                 "backends.static.decompile.decompile_function_angr",
                 return_value={"addr": "0x401000", "code": "int add() { return 1; }", "error": None, "decompiler": "angr"},
             ) as angr_mock, \
             mock.patch(
                 "backends.static.decompile.decompile_function_ghidra",
                 side_effect=AssertionError("ghidra should not be used for explicit angr"),
             ), \
             mock.patch("backends.static.decompile._is_angr_available", return_value=True), \
             mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack):
            result = decompile_function("/bin/ls", "0x401000", decompiler="angr", provider="local", cache_dir=Path(d))

        angr_mock.assert_called_once()
        self.assertEqual(result.get("decompiler"), "angr")
        self.assertIsNone(result.get("error"))

    def test_explicit_angr_binary_dispatch_does_not_fall_back_to_auto(self):
        with mock.patch(
            "backends.static.decompile.decompile_binary_angr",
            return_value={
                "functions": [{"addr": "0x401000", "code": "int add() { return 1; }", "error": None}],
                "code": "int add() { return 1; }",
                "error": None,
                "decompiler": "angr",
            },
        ) as angr_mock, \
        mock.patch(
            "backends.static.decompile.decompile_binary_ghidra",
            side_effect=AssertionError("ghidra should not be used for explicit angr"),
        ), \
        mock.patch("backends.static.decompile._is_angr_available", return_value=True):
            result = decompile_binary("/bin/ls", decompiler="angr", provider="local")

        angr_mock.assert_called_once()
        self.assertEqual(result.get("decompiler"), "angr")
        self.assertIsNone(result.get("error"))

    def test_list_available_decompilers_keeps_curated_trio_visible(self):
        with mock.patch("backends.static.decompile._load_hidden_builtins", return_value=["angr", "r2ghidra", "boomerang"]), \
             mock.patch("backends.static.decompile._is_builtin_available_local", return_value=False), \
             mock.patch("backends.static.decompile._is_docker_decompiler_image_available", return_value=False), \
             mock.patch("backends.static.decompile._load_custom_decompilers", return_value={}):
            result = list_available_decompilers(provider="auto")

        self.assertIn("ghidra", result)
        self.assertIn("retdec", result)
        self.assertIn("angr", result)
        self.assertNotIn("r2ghidra", result)
        self.assertNotIn("r2pdc", result)
        self.assertNotIn("boomerang", result)

    def test_custom_docker_image_is_loaded_from_config(self):
        with tempfile.TemporaryDirectory() as d:
            config_path = Path(d) / "decompilers.json"
            config_path.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "my-ghidra": {
                                "label": "My Ghidra",
                                "command": ["wrapper", "--binary", "{binary}", "--addr", "{addr}"],
                                "docker_image": "registry.example/my-ghidra:latest",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"POF_DECOMPILERS_CONFIG": str(config_path)}, clear=False):
                self.assertEqual(
                    _get_decompiler_docker_image("my-ghidra"),
                    "registry.example/my-ghidra:latest",
                )

    def test_decompile_function_rewrites_typed_struct_addresses(self):
        empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}

        def fake_ghidra(_binary, _addr, func_name=""):
            return {
                "addr": "0x401000",
                "code": "int f() { return *(int *)0x402000; }",
                "error": None,
                "decompiler": "ghidra",
            }

        with tempfile.TemporaryDirectory() as d, \
             mock.patch("backends.static.decompile.decompile_function_ghidra", fake_ghidra), \
             mock.patch("backends.static.decompile._is_ghidra_available", return_value=True), \
             mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack), \
             mock.patch(
                 "backends.static.decompile.build_typed_struct_index",
                 return_value={
                     "exact_by_addr": {
                         "0x402000": {
                             "kind": "field",
                             "label": "Demo.magic",
                             "comment": "struct Demo • champ magic • uint32_t",
                             "addr": "0x402000",
                             "struct_name": "Demo",
                             "field_name": "magic",
                             "field_type": "uint32_t",
                         }
                     }
                 },
             ), \
             mock.patch("backends.static.decompile.typed_struct_signature", return_value="structsig"):
            result = decompile_function(
                "/bin/ls",
                "0x401000",
                decompiler="ghidra",
                provider="local",
                cache_dir=Path(d),
            )

        self.assertIn("Demo.magic", result["code"])
        self.assertEqual(result["typed_structs"][0]["name"], "Demo.magic")

    def test_extract_retdec_function_code_by_addr(self):
        from backends.static.decompile import _extract_retdec_function_code

        sample = (
            "// Address range: 0x401000 - 0x401050\n"
            "int f1() { return 0; }\n"
            "// Address range: 0x401060 - 0x4010a0\n"
            "int f2() { return 1; }\n"
            "// --------------------- Meta-Information ---------------------\n"
        )
        code = _extract_retdec_function_code(sample, addr="0x401060")
        self.assertIn("int f2()", code)
        self.assertNotIn("int f1()", code)

    def test_extract_retdec_function_code_by_name(self):
        from backends.static.decompile import _extract_retdec_function_code

        sample = (
            "// Address range: 0x401000 - 0x401050\n"
            "int f1() { return 0; }\n"
            "// Address range: 0x401060 - 0x4010a0\n"
            "int helper_2() { return 1; }\n"
            "// --------------------- Meta-Information ---------------------\n"
        )
        code = _extract_retdec_function_code(sample, func_name="helper_2")
        self.assertIn("int helper_2()", code)
        self.assertNotIn("int f1()", code)

    def test_cleanup_r2pdc_inlines_missing_direct_call_block(self):
        from backends.static.decompile import _cleanup_r2pdc_code

        sample = (
            "// callconv: rax amd64 (...)\n"
            "int main () {\n"
            "    if (v) goto loc_0x401020;\n"
            "    goto loc_0x401010;\n"
            "    loc_0x401020:\n"
            "        return 0;\n"
            "}\n"
        )
        instruction_map = {
            "0x401010": {"addr": "0x401010", "mnemonic": "call", "operands": "0x402000", "next_addr": "0x401015"},
            "0x401015": {"addr": "0x401015", "mnemonic": "jmp", "operands": "0x401020", "next_addr": ""},
        }
        symbol_map = {"0x402000": "_win"}
        cleaned = _cleanup_r2pdc_code(sample, instruction_map=instruction_map, symbol_map=symbol_map)
        self.assertNotIn("// callconv:", cleaned)
        self.assertIn("win();", cleaned)
        self.assertIn("goto loc_0x401020;", cleaned)

    def test_cleanup_r2pdc_simplifies_printf_argument_setup(self):
        from backends.static.decompile import _cleanup_r2pdc_code

        sample = (
            "int main () {\n"
            "    arg_rsi = dword [var_14]\n"
            "    arg_rdi = rip + 0x4e // str.Try_again // 0x100000516 // \"Try again, you got 0x%08x\\n\"\n"
            "    al = 0\n"
            "    sym.imp.printf ()\n"
            "}\n"
        )
        cleaned = _cleanup_r2pdc_code(sample, instruction_map={}, symbol_map={})
        self.assertIn('printf("Try again, you got 0x%08x\\n", var_14);', cleaned)
        self.assertNotIn("sym.imp.printf", cleaned)

    def test_cleanup_r2pdc_rebuilds_simple_if_else(self):
        from backends.static.decompile import _cleanup_r2pdc_code

        sample = (
            "int main (int argc, char **argv) {\n"
            "    loc_0x401000:\n"
            "        push (rbp)\n"
            "        rbp = rsp\n"
            "        rsp -= 0x20\n"
            "        dword [var_4] = 0\n"
            "        eax = dword [var_4]\n"
            "        v = eax - 0x43434343 // 'CCCC'\n"
            "        if (v) goto loc_0x401020 // likely\n"
            "        win()\n"
            "        goto loc_0x401030;\n"
            "    loc_0x401020:\n"
            "        printf(\"nope\", var_4)\n"
            "    loc_0x401030:\n"
            "        eax = dword [var_4]\n"
            "        rsp += 0x20\n"
            "        rbp = pop ()\n"
            "        return rax;\n"
            "}\n"
        )
        cleaned = _cleanup_r2pdc_code(sample, instruction_map={}, symbol_map={})
        self.assertIn("if (var_4 == 0x43434343) {", cleaned)
        self.assertIn("win();", cleaned)
        self.assertIn("} else {", cleaned)
        self.assertIn('printf("nope", var_4);', cleaned)
        self.assertIn("return 0;", cleaned)
        self.assertNotIn("push (rbp)", cleaned)
        self.assertNotIn("loc_0x401020:", cleaned)

    def test_score_decompile_code_rewards_expected_calls(self):
        plain = _score_decompile_code("int main(){ return 0; }", "retdec", expected_calls={"win"})
        with_call = _score_decompile_code("int main(){ win(); return 0; }", "r2pdc", expected_calls={"win"})
        self.assertGreater(with_call["score"], plain["score"])
        self.assertEqual(with_call["metrics"]["matched_calls"], 1)

    def test_normalize_quality_accepts_precision(self):
        self.assertEqual(_normalize_quality("precision"), "precision")

    def test_normalize_quality_maps_max_to_precision(self):
        self.assertEqual(_normalize_quality("max"), "precision")

    def test_precision_score_prefers_faithful_output(self):
        pretty_but_wrong = _score_decompile_code(
            'int main(){ printf("Try again, you got 0x%08x\\n", 0); return 0; }',
            "retdec",
            expected_calls={"win"},
            quality="precision",
        )
        uglier_but_faithful = _score_decompile_code(
            "int main(){ if (v) goto loc_0x1; win(); loc_0x1: return 0; }",
            "r2pdc",
            expected_calls={"win"},
            quality="precision",
        )
        self.assertGreater(uglier_but_faithful["score"], pretty_but_wrong["score"])
        self.assertEqual(uglier_but_faithful["metrics"]["matched_calls"], 1)
        self.assertEqual(pretty_but_wrong["metrics"]["missed_calls"], 1)

    def test_parse_c_like_function_blocks_skips_import_stubs(self):
        sample = (
            "void __stdcall sym.imp.printf(char *format)\n"
            "{\n"
            "    return;\n"
            "}\n\n"
            "int main(int argc, char **argv)\n"
            "{\n"
            "    return 0;\n"
            "}\n\n"
            "int64_t sym._helper(void)\n"
            "{\n"
            "    return 1;\n"
            "}\n"
        )
        parsed = _parse_c_like_function_blocks(sample)
        self.assertEqual([entry["name"] for entry in parsed], ["main", "sym._helper"])
        self.assertEqual(len(parsed), 2)

    def test_parse_c_like_function_blocks_handles_same_line_brace(self):
        sample = (
            "int main (int argc, char **argv) {\n"
            "    return 0;\n"
            "}\n"
        )
        parsed = _parse_c_like_function_blocks(sample)
        self.assertEqual(len(parsed), 1)
        self.assertIn("return 0;", parsed[0]["code"])

    def test_decompile_binary_nonexistent_returns_error(self):
        r = decompile_binary("/nonexistent/binary")
        self.assertIn("error", r)
        self.assertIsNotNone(r["error"])

    def test_load_custom_decompilers_from_config(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / "decompilers.json"
            config.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "my ghidra": {
                                "label": "My Ghidra",
                                "command": ["echo", "{\"code\":\"int f(){return 1;}\"}"],
                            },
                            "retdec": {
                                "command": ["ignored"],
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            loaded = _load_custom_decompilers(config)
        self.assertIn("my-ghidra", loaded)
        self.assertEqual(loaded["my-ghidra"]["label"], "My Ghidra")
        self.assertNotIn("retdec", loaded)

    def test_run_custom_decompiler_parses_json_stdout(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write("bin")
            binary_path = tmp.name
        try:
            with tempfile.TemporaryDirectory() as d:
                config = Path(d) / "decompilers.json"
                config.write_text(
                    json.dumps(
                        {
                            "decompilers": {
                                "toy": {
                                    "command": [
                                        sys.executable,
                                        "-c",
                                        "import json; print(json.dumps({'code':'int toy(){return 7;}'}))",
                                    ]
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                with mock.patch.dict(os.environ, {"POF_DECOMPILERS_CONFIG": str(config)}):
                    result = _run_custom_decompiler("toy", binary_path, addr="0x401000")
            self.assertIsNone(result.get("error"))
            self.assertEqual(result.get("decompiler"), "toy")
            self.assertIn("return 7", result.get("code", ""))
        finally:
            Path(binary_path).unlink(missing_ok=True)

    def test_resolve_function_target_matches_symbol_aliases(self):
        fake_symbols = [
            {"addr": "0x100000490", "name": "_main"},
            {"addr": "0x100000470", "name": "_win"},
        ]
        with mock.patch("backends.static.symbols.extract_symbols", return_value=fake_symbols), \
             mock.patch("backends.static.decompile._collect_decompile_targets", return_value=[]):
            addr, func_name = _resolve_function_target("/tmp/demo.bin", "0x4011a6", "_main")
        self.assertEqual(addr, "0x100000490")
        self.assertEqual(func_name, "_main")

    def test_decompile_function_prefers_resolved_func_name_address(self):
        empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}

        def fake_ghidra(_binary, resolved_addr, func_name=""):
            return {
                "addr": resolved_addr,
                "code": f"int {func_name or 'main'}() {{ return 0; }}",
                "error": None,
                "decompiler": "ghidra",
            }

        fake_symbols = [{"addr": "0x100000490", "name": "_main"}]
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("backends.static.decompile.decompile_function_ghidra", fake_ghidra), \
             mock.patch("backends.static.decompile._is_ghidra_available", return_value=True), \
             mock.patch("backends.static.stack_frame.analyse_stack_frame", return_value=empty_stack), \
             mock.patch("backends.static.symbols.extract_symbols", return_value=fake_symbols), \
             mock.patch("backends.static.decompile._collect_decompile_targets", return_value=[]), \
             mock.patch("backends.static.decompile.typed_struct_signature", return_value="structsig"):
            result = decompile_function(
                "/bin/ls",
                "0x4011a6",
                func_name="_main",
                decompiler="ghidra",
                provider="local",
                cache_dir=Path(d),
            )

        self.assertIsNone(result["error"])
        self.assertEqual(result["addr"], "0x100000490")
        self.assertIn("_main", result["code"])


if __name__ == "__main__":
    unittest.main()
