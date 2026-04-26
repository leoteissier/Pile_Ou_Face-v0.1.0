"""Unit tests for backends.mcp.ollama_bridge helpers."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.mcp.ollama_bridge import (
    _build_system_prompt,
    _auto_tool_fallback,
    _coerce_tool_arguments,
    _detect_tool_intent,
    _default_server_cmd,
    _extract_binary_candidate,
    _normalize_tool_call_arguments,
    _resolve_binary_from_prompt,
    _select_mcp_tools_for_prompt,
    _looks_like_noop_response,
    _prompt_likely_needs_tools,
    _resolve_requested_tool_name,
    mcp_tool_to_ollama_tool,
)


class TestOllamaBridgeHelpers(unittest.TestCase):
    class _FakeClient:
        def __init__(self, payload):
            self.payload = payload
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            return {"structuredContent": self.payload}

    class _FakeClientByTool:
        def __init__(self, payload_by_tool):
            self.payload_by_tool = payload_by_tool
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            name = params.get("name")
            return {"structuredContent": self.payload_by_tool.get(name, {"ok": False})}

    class _FakeFindClient:
        def __init__(self, results):
            self.results = results
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            if params.get("name") == "find_files":
                return {
                    "structuredContent": {
                        "ok": True,
                        "results": self.results,
                    }
                }
            return {"structuredContent": {"ok": False}}

    def test_mcp_tool_to_ollama_tool(self):
        tool = {
            "name": "get_symbols",
            "description": "Extract symbols",
            "inputSchema": {
                "type": "object",
                "properties": {"binary_path": {"type": "string"}},
                "required": ["binary_path"],
            },
        }
        converted = mcp_tool_to_ollama_tool(tool)
        self.assertEqual(converted["type"], "function")
        self.assertEqual(converted["function"]["name"], "get_symbols")
        self.assertIn("parameters", converted["function"])

    def test_coerce_tool_arguments_from_dict(self):
        args = {"binary_path": "/tmp/a.elf"}
        self.assertEqual(_coerce_tool_arguments(args), args)

    def test_coerce_tool_arguments_from_json_string(self):
        parsed = _coerce_tool_arguments('{"binary_path": "/tmp/a.elf", "addr": "0x401000"}')
        self.assertEqual(parsed["binary_path"], "/tmp/a.elf")
        self.assertEqual(parsed["addr"], "0x401000")

    def test_coerce_tool_arguments_empty_string(self):
        self.assertEqual(_coerce_tool_arguments(""), {})

    def test_coerce_tool_arguments_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            _coerce_tool_arguments("{invalid json")

    def test_default_server_cmd_points_to_mcp_server(self):
        cmd = _default_server_cmd()
        self.assertIn("backends/mcp/server.py", cmd)

    def test_looks_like_noop_response(self):
        self.assertTrue(_looks_like_noop_response("Please provide a request."))
        self.assertTrue(_looks_like_noop_response("Please provide a file or a request."))
        self.assertTrue(
            _looks_like_noop_response(
                "I still need a file or a specific request to use the available tools."
            )
        )
        self.assertFalse(_looks_like_noop_response("Voici les 5 premieres instructions..."))

    def test_prompt_likely_needs_tools(self):
        self.assertTrue(_prompt_likely_needs_tools("Analyse demo_analysis.elf"))
        self.assertTrue(_prompt_likely_needs_tools("disassemble ce binaire"))
        self.assertTrue(_prompt_likely_needs_tools("donne le code asm de vuln_demo.elf"))
        self.assertFalse(_prompt_likely_needs_tools("dis moi bonjour"))

    def test_detect_tool_intent(self):
        self.assertEqual(_detect_tool_intent("Donne le code ASM"), "disassemble")
        self.assertEqual(_detect_tool_intent("Trouve les symboles"), "symbols")
        self.assertEqual(_detect_tool_intent("Liste les strings"), "strings")
        self.assertIsNone(_detect_tool_intent("dis moi bonjour"))

    def test_extract_binary_candidate(self):
        self.assertEqual(
            _extract_binary_candidate("Analyse examples/demo_analysis.elf"),
            "examples/demo_analysis.elf",
        )
        self.assertIsNone(_extract_binary_candidate("Analyse ce fichier"))

    def test_auto_tool_fallback_disassemble(self):
        payload = {
            "ok": True,
            "count": 3,
            "lines": [
                {"addr": "0x1", "text": "55 push rbp"},
                {"addr": "0x2", "text": "48 89 e5 mov rbp, rsp"},
            ],
        }
        client = self._FakeClient(payload)
        out = _auto_tool_fallback(client, "disassemble demo_analysis.elf")
        assert out is not None
        self.assertIn("Désassemblage", out)
        self.assertIn("demo_analysis.elf", out)
        self.assertEqual(client.calls[0][1]["name"], "disassemble")

    def test_auto_tool_fallback_disassemble_from_asm_prompt(self):
        payload = {
            "ok": True,
            "count": 1,
            "lines": [{"addr": "0x1000", "text": "ret"}],
        }
        client = self._FakeClient(payload)
        out = _auto_tool_fallback(client, "Donne le code ASM de vuln_demo.elf")
        assert out is not None
        self.assertIn("Désassemblage", out)
        self.assertEqual(client.calls[0][1]["name"], "disassemble")

    def test_auto_tool_fallback_binary_info_when_intent_missing(self):
        client = self._FakeClientByTool(
            {
                "get_binary_info": {
                    "ok": True,
                    "format": "ELF",
                    "arch": "x86_64",
                    "bits": 64,
                }
            }
        )
        out = _auto_tool_fallback(client, "le fichier c'est vul_demo.elf")
        assert out is not None
        self.assertIn("Fichier pris en compte", out)
        self.assertEqual(client.calls[0][1]["name"], "get_binary_info")

    def test_resolve_binary_from_prompt_via_find_files_hint(self):
        client = self._FakeFindClient(
            [{"path": "/repo/examples/vuln_demo.elf", "relative_path": "examples/vuln_demo.elf"}]
        )
        out = _resolve_binary_from_prompt(client, "le fichier c'est vul_demo")
        self.assertEqual(out, "/repo/examples/vuln_demo.elf")
        self.assertEqual(client.calls[0][1]["name"], "find_files")

    def test_normalize_tool_call_arguments_adds_binary_and_default_max_lines(self):
        client = self._FakeFindClient(
            [{"path": "/repo/examples/vuln_demo.elf", "relative_path": "examples/vuln_demo.elf"}]
        )
        normalized = _normalize_tool_call_arguments(
            client,
            "disassemble",
            {"max_lines": "oops"},
            "analyse vul_demo",
        )
        self.assertEqual(normalized["binary_path"], "/repo/examples/vuln_demo.elf")
        self.assertEqual(normalized["max_lines"], 120)

    def test_select_mcp_tools_for_prompt_disassemble_intent(self):
        tools = [
            {"name": "disassemble"},
            {"name": "find_files"},
            {"name": "get_symbols"},
            {"name": "get_binary_info"},
            {"name": "capa_scan"},
        ]
        selected = _select_mcp_tools_for_prompt(tools, "donne le code asm de vuln_demo.elf")
        names = {tool["name"] for tool in selected}
        self.assertIn("disassemble", names)
        self.assertIn("find_files", names)
        self.assertNotIn("capa_scan", names)

    def test_resolve_requested_tool_name_alias(self):
        available = {"extract_strings", "get_symbols", "disassemble"}
        self.assertEqual(
            _resolve_requested_tool_name("strings", available),
            "extract_strings",
        )
        self.assertEqual(
            _resolve_requested_tool_name("DISASM", available),
            "disassemble",
        )
        self.assertEqual(
            _resolve_requested_tool_name("unknown_tool", available),
            "unknown_tool",
        )

    def test_build_system_prompt_appends_memory_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_path = Path(tmpdir) / "memory.md"
            memory_path.write_text("MCP memory context", encoding="utf-8")
            prompt = _build_system_prompt("Base system prompt", str(memory_path))
        assert prompt is not None
        self.assertIn("Base system prompt", prompt)
        self.assertIn("MCP memory context", prompt)
        self.assertIn("Additional project context", prompt)


if __name__ == "__main__":
    unittest.main()
