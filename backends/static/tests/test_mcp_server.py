"""Unit tests for backends.mcp_server."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends import mcp_server
from backends.mcp import server as mcp_impl


class TestMcpServer(unittest.TestCase):
    def test_initialize(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["id"], 1)
        self.assertIn("result", response)
        self.assertIn("capabilities", response["result"])
        self.assertIn("serverInfo", response["result"])

    @patch("backends.mcp.server._load_mcp_memory_context")
    def test_initialize_includes_instructions_when_memory_is_available(self, mock_memory):
        mock_memory.return_value = "MCP memory context"
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertIn("instructions", result)
        self.assertIn("MCP memory context", result["instructions"])

    def test_tools_list_contains_expected_names(self):
        request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        tools = response["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertIn("get_binary_info", names)
        self.assertIn("disassemble", names)
        self.assertIn("get_symbols", names)
        self.assertIn("extract_strings", names)
        self.assertIn("get_xrefs", names)
        self.assertIn("find_files", names)

    @patch("backends.mcp_server.pof.symbols")
    def test_tools_call_get_symbols(self, mock_symbols):
        mock_symbols.return_value = {"ok": True, "symbols": [{"name": "main"}]}
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "get_symbols",
                    "arguments": {"binary_path": binary_path},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_symbols.assert_called_once_with(binary_path)

    @patch("backends.mcp.server._find_files")
    def test_tools_call_find_files(self, mock_find_files):
        mock_find_files.return_value = {"ok": True, "count": 1, "results": []}
        request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "find_files",
                "arguments": {"query": "demo_analysis.elf"},
            },
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["ok"], True)
        mock_find_files.assert_called_once_with("demo_analysis.elf", limit=20)

    @patch("backends.mcp.server._call_tool")
    def test_tools_call_alias_strings_resolves_to_extract_strings(self, mock_call_tool):
        mock_call_tool.return_value = {"ok": True, "strings": ["hello"]}
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 33,
                "method": "tools/call",
                "params": {
                    "name": "strings",
                    "arguments": {"binary_path": binary_path},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_call_tool.assert_called_once_with("extract_strings", {"binary_path": binary_path})

    def test_tools_call_invalid_params_returns_tool_error_payload(self):
        with tempfile.NamedTemporaryFile() as tmp:
            request = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "get_xrefs",
                    "arguments": {"binary_path": str(Path(tmp.name).resolve())},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertTrue(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], False)
            self.assertIn("addr", result["structuredContent"]["error"])

    @patch("backends.mcp.server._disassemble_for_mcp")
    def test_tools_call_disassemble_without_output_param(self, mock_disassemble):
        mock_disassemble.return_value = {"ok": True, "count": 2, "lines": [{"addr": "0x1"}]}
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "disassemble",
                    "arguments": {"binary_path": binary_path},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_disassemble.assert_called_once_with(binary_path, addr=None, max_lines=400)

    def test_tools_call_disassemble_invalid_max_lines(self):
        with tempfile.NamedTemporaryFile() as tmp:
            request = {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "disassemble",
                    "arguments": {
                        "binary_path": str(Path(tmp.name).resolve()),
                        "max_lines": "bad",
                    },
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertTrue(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], False)
            self.assertIn("max_lines", result["structuredContent"]["error"])

    def test_unknown_method_returns_jsonrpc_error(self):
        request = {"jsonrpc": "2.0", "id": 5, "method": "does/not/exist"}
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], mcp_server.JSONRPC_METHOD_NOT_FOUND)

    @patch("backends.mcp.server._iter_workspace_files")
    @patch("backends.mcp.server.os.path.isfile")
    def test_resolve_binary_path_with_basename_search(self, mock_isfile, mock_iter_files):
        mock_isfile.return_value = False
        mock_iter_files.return_value = [
            "/repo/examples/demo_analysis.elf",
            "/repo/other/file.txt",
        ]
        resolved = mcp_impl._resolve_binary_path("demo_analysis.elf")
        self.assertEqual(resolved, "/repo/examples/demo_analysis.elf")

    @patch("backends.mcp.server._iter_workspace_files")
    @patch("backends.mcp.server.os.path.isfile")
    def test_resolve_binary_path_with_fuzzy_basename(self, mock_isfile, mock_iter_files):
        mock_isfile.return_value = False
        mock_iter_files.return_value = [
            "/repo/examples/vuln_demo.elf",
            "/repo/examples/demo_analysis.elf",
        ]
        resolved = mcp_impl._resolve_binary_path("vul_demo.elf")
        self.assertEqual(resolved, "/repo/examples/vuln_demo.elf")


if __name__ == "__main__":
    unittest.main()
