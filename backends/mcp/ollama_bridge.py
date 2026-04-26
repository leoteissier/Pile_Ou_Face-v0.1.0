#!/usr/bin/env python3
"""Bridge between Ollama tool-calling and the local MCP server.

This script allows a local Ollama model to call MCP tools exposed by:
    backends/mcp/server.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Any
from urllib import error, request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
DEFAULT_MEMORY_PATH = os.path.join(ROOT, "docs", "mcp", "memory.md")
LEGACY_DOCS_MEMORY_PATH = os.path.join(ROOT, "docs", "mcp", "docs", "memory.md")
LEGACY_ROOT_MEMORY_PATH = os.path.join(ROOT, "memory.md")

DEFAULT_DISASM_MAX_LINES = 120
DEFAULT_MEMORY_MAX_CHARS = 6000
KNOWN_BINARY_EXTENSIONS = (
    ".elf",
    ".exe",
    ".bin",
    ".dll",
    ".so",
    ".dylib",
    ".macho",
)

TOOL_NAME_ALIASES: dict[str, str] = {
    "strings": "extract_strings",
    "string": "extract_strings",
    "symbols": "get_symbols",
    "symboles": "get_symbols",
    "symbol": "get_symbols",
    "disasm": "disassemble",
    "asm": "disassemble",
    "xref": "get_xrefs",
    "xrefs": "get_xrefs",
    "sections": "get_sections",
    "imports": "analyze_imports",
    "vulns": "find_vulnerabilities",
    "vulns_scan": "find_vulnerabilities",
    "rop": "find_rop_gadgets",
    "callgraph": "build_call_graph",
    "call_graph": "build_call_graph",
    "cfg_function": "build_cfg_for_function",
    "binary_info": "get_binary_info",
}


class McpStdioClient:
    """Minimal JSON-RPC client over MCP stdio framing."""

    def __init__(self, cmd: list[str], cwd: str, timeout_s: int = 60) -> None:
        self.cmd = cmd
        self.cwd = cwd
        self.timeout_s = timeout_s
        self.proc: subprocess.Popen[bytes] | None = None
        self._next_id = 1

    def start(self) -> None:
        if self.proc is not None:
            return
        self.proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
        )

    def close(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._write_message(payload)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._write_message(payload)
        response = self._read_message()
        if response.get("id") != req_id:
            raise RuntimeError(f"Unexpected response id: {response.get('id')} != {req_id}")
        if "error" in response:
            err = response["error"]
            raise RuntimeError(f"MCP error {err.get('code')}: {err.get('message')}")
        return response.get("result", {})

    def _pipes(self) -> tuple[Any, Any]:
        if self.proc is None or self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("MCP process is not running")
        return self.proc.stdin, self.proc.stdout

    def _write_message(self, message: dict[str, Any]) -> None:
        stdin, _ = self._pipes()
        body = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
        stdin.write(frame)
        stdin.flush()

    def _read_message(self) -> dict[str, Any]:
        _, stdout = self._pipes()
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = stdout.read(1)
            if not chunk:
                raise RuntimeError("EOF while reading MCP headers")
            header += chunk

        head, _ = header.split(b"\r\n\r\n", 1)
        content_length = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
                break
        if content_length is None:
            raise RuntimeError("MCP response missing Content-Length")

        payload = stdout.read(content_length)
        if len(payload) != content_length:
            raise RuntimeError("Unexpected EOF while reading MCP payload")
        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("Invalid JSON in MCP response") from exc


def mcp_tool_to_ollama_tool(mcp_tool: dict[str, Any]) -> dict[str, Any]:
    """Convert MCP tool schema to Ollama function-tool schema."""
    name = str(mcp_tool.get("name", ""))
    desc = str(mcp_tool.get("description", ""))
    params = mcp_tool.get("inputSchema")
    if not isinstance(params, dict):
        params = {"type": "object", "properties": {}, "additionalProperties": True}
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": params,
        },
    }


def _coerce_tool_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        value = raw.strip()
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Tool arguments are not valid JSON: {value}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Tool arguments JSON must decode to an object")
        return parsed
    return {}


def _looks_like_noop_response(text: str) -> bool:
    t = text.strip().lower()
    if not t:
        return True
    direct_hints = [
        "please provide a request",
        "please provide a file",
        "please provide the file",
        "ready to assist",
        "provide a task",
        "i still need a file",
        "need a file or",
    ]
    if any(h in t for h in direct_hints):
        return True

    generic_patterns = [
        r"\bplease provide\b.*\b(file|request|task)\b",
        r"\b(i\s+)?need\b.*\b(file|path|request)\b",
    ]
    return any(re.search(pat, t) is not None for pat in generic_patterns)


def _prompt_likely_needs_tools(prompt: str) -> bool:
    p = prompt.lower()
    if _detect_tool_intent(p):
        return True
    return any(
        token in p
        for token in [
            ".elf",
            ".exe",
            ".bin",
            "xrefs",
            "analyse",
            "analyze",
            "asm",
            "mcp",
        ]
    )


def _detect_tool_intent(prompt: str) -> str | None:
    p = prompt.lower()
    disasm_tokens = (
        "disassemble",
        "disasm",
        "desassemble",
        "dessasemble",
        "désassemble",
        "desassemblage",
        "désassemblage",
        "assembleur",
        "assembly",
        "code asm",
    )
    if any(token in p for token in disasm_tokens) or re.search(r"\basm\b", p):
        return "disassemble"

    symbol_tokens = (
        "symbol",
        "symbole",
    )
    if any(token in p for token in symbol_tokens):
        return "symbols"

    strings_tokens = (
        "strings",
        "chaine",
        "chaîne",
    )
    if any(token in p for token in strings_tokens):
        return "strings"
    return None


def _extract_binary_candidate(prompt: str) -> str | None:
    pattern = re.compile(
        r"([A-Za-z0-9_./\\-]+\.(?:elf|exe|bin|dll|so|dylib|macho|mach-o))",
        re.IGNORECASE,
    )
    match = pattern.search(prompt)
    if not match:
        return None
    return match.group(1)


def _extract_filename_hints(prompt: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_./\\-]{3,}", prompt)
    stopwords = {
        "analyse",
        "analysis",
        "disassemble",
        "desassemble",
        "dessasemble",
        "disasm",
        "symbols",
        "symboles",
        "strings",
        "mcp",
        "outil",
        "tools",
        "code",
    }
    hints: list[str] = []
    for token in tokens:
        t = token.strip().strip(".,;:!?\"'()[]{}")
        if not t:
            continue
        if t.lower() in stopwords:
            continue
        hints.append(t)
    seen = set()
    unique: list[str] = []
    for hint in hints:
        if hint in seen:
            continue
        seen.add(hint)
        unique.append(hint)
    return unique


def _select_best_file_from_find_results(
    query: str, results: list[dict[str, Any]]
) -> str | None:
    if not results:
        return None
    query_low = query.lower()
    has_ext = "." in os.path.basename(query_low)

    scored: list[tuple[int, str]] = []
    for item in results:
        path = str(item.get("path", "")).strip()
        if not path:
            continue
        rel = str(item.get("relative_path", "")).strip()
        basename = os.path.basename(path).lower()
        rel_low = rel.lower()
        ext = os.path.splitext(basename)[1]
        is_binary_like = ext in KNOWN_BINARY_EXTENSIONS
        score = 100
        if has_ext and basename == os.path.basename(query_low):
            score = 0
        elif is_binary_like and query_low in basename:
            score = 5
        elif is_binary_like and query_low in rel_low:
            score = 10
        elif is_binary_like:
            score = 20
        elif query_low in basename:
            score = 30
        if "/examples/" in path.replace("\\", "/"):
            score -= 1
        scored.append((score, path))

    if not scored:
        return None
    scored.sort(key=lambda item: (item[0], len(item[1]), item[1]))
    return scored[0][1]


def _resolve_binary_from_prompt(client: McpStdioClient, prompt: str) -> str | None:
    direct = _extract_binary_candidate(prompt)
    if direct:
        return direct
    hints = _extract_filename_hints(prompt)
    if not hints:
        return None
    for hint in hints[:6]:
        try:
            find_result = client.request(
                "tools/call",
                {"name": "find_files", "arguments": {"query": hint, "limit": 12}},
            )
        except Exception:
            continue
        payload = find_result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            continue
        results = payload.get("results", [])
        if not isinstance(results, list):
            continue
        selected = _select_best_file_from_find_results(hint, results)
        if selected:
            return selected
    return None


def _normalize_tool_call_arguments(
    client: McpStdioClient, name: str, args: dict[str, Any], prompt: str
) -> dict[str, Any]:
    normalized = dict(args)
    needs_binary = name in {
        "disassemble",
        "get_symbols",
        "extract_strings",
        "get_binary_info",
        "get_sections",
        "get_xrefs",
        "discover_functions",
        "analyze_imports",
        "analyze_behavior",
        "find_vulnerabilities",
        "find_rop_gadgets",
        "deobfuscate_strings",
    }
    if needs_binary:
        raw_binary = normalized.get("binary_path", normalized.get("binary"))
        if not isinstance(raw_binary, str) or not raw_binary.strip():
            inferred = _resolve_binary_from_prompt(client, prompt)
            if inferred:
                normalized["binary_path"] = inferred
    if name == "disassemble":
        raw_max = normalized.get("max_lines")
        try:
            max_lines = int(raw_max) if raw_max is not None else DEFAULT_DISASM_MAX_LINES
        except (TypeError, ValueError):
            max_lines = DEFAULT_DISASM_MAX_LINES
        if max_lines <= 0:
            max_lines = DEFAULT_DISASM_MAX_LINES
        normalized["max_lines"] = max_lines
    return normalized


def _resolve_requested_tool_name(name: str, available_tool_names: set[str]) -> str:
    raw = name.strip()
    if not raw:
        return raw
    if raw in available_tool_names:
        return raw
    candidate = raw.lower().replace("-", "_")
    if candidate in available_tool_names:
        return candidate
    alias = TOOL_NAME_ALIASES.get(candidate)
    if isinstance(alias, str) and alias in available_tool_names:
        return alias
    return raw


def _select_mcp_tools_for_prompt(mcp_tools: list[dict[str, Any]], prompt: str) -> list[dict[str, Any]]:
    intent = _detect_tool_intent(prompt)
    if not intent:
        return mcp_tools
    names_by_intent: dict[str, set[str]] = {
        "disassemble": {"disassemble", "find_files", "get_binary_info", "get_symbols"},
        "symbols": {"get_symbols", "find_files", "get_binary_info", "disassemble"},
        "strings": {"extract_strings", "find_files", "get_binary_info", "disassemble"},
    }
    allowed = names_by_intent.get(intent, set())
    if not allowed:
        return mcp_tools
    selected = [
        tool
        for tool in mcp_tools
        if isinstance(tool, dict) and str(tool.get("name", "")) in allowed
    ]
    return selected or mcp_tools


def _auto_tool_fallback(client: McpStdioClient, prompt: str) -> str | None:
    intent = _detect_tool_intent(prompt)
    binary = _resolve_binary_from_prompt(client, prompt)
    if not binary:
        return None

    if intent == "disassemble":
        result = client.request(
            "tools/call",
            {"name": "disassemble", "arguments": {"binary_path": binary, "max_lines": 60}},
        )
        payload = result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        lines = payload.get("lines", [])
        if not isinstance(lines, list):
            lines = []
        head = lines[:8]
        out = [
            (
                f"Désassemblage de {binary}: {payload.get('count', len(lines))} instructions "
                f"(aperçu {len(head)})."
            )
        ]
        for idx, line in enumerate(head, start=1):
            if not isinstance(line, dict):
                continue
            addr = str(line.get("addr", "")).strip()
            text = str(line.get("text", "")).strip()
            out.append(f"{idx}. {addr} {text}".strip())
        return "\n".join(out)

    if intent == "symbols":
        result = client.request(
            "tools/call",
            {"name": "get_symbols", "arguments": {"binary_path": binary}},
        )
        payload = result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        symbols = payload.get("symbols", [])
        if not isinstance(symbols, list):
            symbols = []
        head = symbols[:12]
        out = [f"Symboles pour {binary}: {len(symbols)} entrées (aperçu {len(head)})."]
        for idx, item in enumerate(head, start=1):
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            addr = item.get("addr", "")
            out.append(f"{idx}. {name} {addr}".strip())
        return "\n".join(out)

    if intent == "strings":
        result = client.request(
            "tools/call",
            {"name": "extract_strings", "arguments": {"binary_path": binary}},
        )
        payload = result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        strings = payload.get("strings", [])
        if not isinstance(strings, list):
            strings = []
        head = strings[:12]
        out = [f"Strings pour {binary}: {len(strings)} entrées (aperçu {len(head)})."]
        for idx, item in enumerate(head, start=1):
            out.append(f"{idx}. {str(item)}")
        return "\n".join(out)

    result = client.request(
        "tools/call",
        {"name": "get_binary_info", "arguments": {"binary_path": binary}},
    )
    payload = result.get("structuredContent", {})
    if not isinstance(payload, dict) or not payload.get("ok"):
        return None
    fmt = payload.get("format") or payload.get("type") or "unknown"
    arch = payload.get("arch") or payload.get("architecture") or "unknown"
    bits = payload.get("bits")
    bits_text = f"{bits}-bit" if bits is not None else "bits inconnus"
    return (
        f"Fichier pris en compte: {binary}. "
        f"Format: {fmt}. Architecture: {arch} ({bits_text}). "
        "Tu peux demander explicitement: disassemble, get_symbols ou extract_strings."
    )

    return None


def _load_memory_context(memory_path: str | None, max_chars: int = DEFAULT_MEMORY_MAX_CHARS) -> str:
    candidates: list[str] = []
    if isinstance(memory_path, str) and memory_path.strip():
        candidates.append(memory_path.strip())
    for fallback in (DEFAULT_MEMORY_PATH, LEGACY_DOCS_MEMORY_PATH, LEGACY_ROOT_MEMORY_PATH):
        if fallback not in candidates:
            candidates.append(fallback)

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
        except OSError:
            continue
        if not content:
            continue
        if len(content) <= max_chars:
            return content
        return content[:max_chars].rstrip() + "\n...[truncated]"
    return ""


def _build_system_prompt(base_prompt: str | None, memory_path: str | None) -> str | None:
    base = (base_prompt or "").strip()
    memory = _load_memory_context(memory_path)
    if not memory:
        return base or None
    memory_block = (
        "Additional project context from docs/mcp/memory.md:\n"
        f"{memory}"
    )
    if not base:
        return memory_block
    return f"{base}\n\n{memory_block}"


def ollama_chat(
    base_url: str,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    timeout_s: int,
) -> dict[str, Any]:
    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
    }
    url = base_url.rstrip("/") + "/api/chat"
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8")
    except error.URLError as exc:
        raise RuntimeError(f"Cannot reach Ollama at {url}: {exc}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid JSON from Ollama /api/chat") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Unexpected Ollama response shape")
    if "error" in parsed:
        raise RuntimeError(f"Ollama error: {parsed['error']}")
    return parsed


def run_agent_once(
    client: McpStdioClient,
    base_url: str,
    model: str,
    prompt: str,
    max_steps: int,
    timeout_s: int,
    system_prompt: str | None = None,
) -> str:
    tools_result = client.request("tools/list", {})
    mcp_tools = tools_result.get("tools", [])
    if not isinstance(mcp_tools, list):
        raise RuntimeError("MCP tools/list returned unexpected payload")
    selected_tools = _select_mcp_tools_for_prompt(
        [t for t in mcp_tools if isinstance(t, dict)],
        prompt,
    )
    ollama_tools = [mcp_tool_to_ollama_tool(t) for t in selected_tools]
    available_tool_names = {
        str(tool.get("name", "")).strip()
        for tool in selected_tools
        if isinstance(tool, dict) and str(tool.get("name", "")).strip()
    }

    messages: list[dict[str, Any]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    last_content = ""
    retried_after_noop = False
    for _ in range(max_steps):
        response = ollama_chat(
            base_url=base_url,
            model=model,
            messages=messages,
            tools=ollama_tools,
            timeout_s=timeout_s,
        )
        message = response.get("message", {})
        if not isinstance(message, dict):
            raise RuntimeError("Ollama response missing 'message' object")

        assistant_entry: dict[str, Any] = {
            "role": "assistant",
            "content": str(message.get("content", "")),
        }
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            assistant_entry["tool_calls"] = tool_calls
        messages.append(assistant_entry)
        last_content = assistant_entry.get("content", "")

        if not isinstance(tool_calls, list) or not tool_calls:
            if (
                not retried_after_noop
                and _prompt_likely_needs_tools(prompt)
                and _looks_like_noop_response(last_content)
            ):
                retried_after_noop = True
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "You already have enough context. Use tools now. "
                            "If filename is uncertain, call find_files first. "
                            "Do not ask the user for CLI commands or extra arguments."
                        ),
                    }
                )
                continue
            if _prompt_likely_needs_tools(prompt) and _looks_like_noop_response(last_content):
                fallback = _auto_tool_fallback(client, prompt)
                if fallback:
                    return fallback
            return last_content

        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function", {})
            if not isinstance(fn, dict):
                continue
            name = fn.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            requested_name = name.strip()
            name = _resolve_requested_tool_name(requested_name, available_tool_names)
            args = _coerce_tool_arguments(fn.get("arguments"))
            args = _normalize_tool_call_arguments(client, name, args, prompt)
            try:
                tool_result = client.request(
                    "tools/call",
                    {"name": name, "arguments": args},
                )
            except Exception as exc:
                tool_result = {
                    "structuredContent": {
                        "ok": False,
                        "error": str(exc),
                        "requested_tool": requested_name,
                        "tool": name,
                        "arguments": args,
                    },
                    "content": [],
                    "isError": True,
                }
            content_list = tool_result.get("content")
            tool_content = ""
            if isinstance(content_list, list) and content_list:
                first = content_list[0]
                if isinstance(first, dict) and isinstance(first.get("text"), str):
                    tool_content = first["text"]
            if not tool_content:
                tool_content = json.dumps(
                    tool_result.get("structuredContent", tool_result), ensure_ascii=True
                )
            messages.append(
                {
                    "role": "tool",
                    "tool_name": name,
                    "content": tool_content,
                }
            )

    return last_content


def _default_server_cmd() -> str:
    server_path = os.path.join(ROOT, "backends", "mcp", "server.py")
    venv_python = os.path.join(ROOT, "backends", ".venv", "bin", "python3")
    python_exe = venv_python if os.path.isfile(venv_python) else sys.executable
    return f"{shlex.quote(python_exe)} {shlex.quote(server_path)} --transport stdio"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ollama <-> MCP bridge runner")
    parser.add_argument("--model", default="qwen3:8b", help="Ollama model name")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:11434",
        help="Base URL of the Ollama API",
    )
    parser.add_argument("--prompt", default="", help="User prompt (one-shot mode)")
    parser.add_argument(
        "--system",
        default=(
            "You can use tools when useful. Prefer tools over guessing. "
            "If a binary path is missing or ambiguous, call find_files first. "
            "Understand natural requests like 'analyse', 'code asm', 'desassemblage', "
            "'symboles', 'strings'. "
            "Do not ask the user to run CLI commands for tools (like --output); "
            "call the tools directly with JSON arguments. "
            "If the user gives a filename (like demo_analysis.elf), use it directly."
        ),
        help="System prompt for the agent loop",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=8,
        help="Max tool-calling iterations per prompt",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=90,
        help="HTTP timeout (seconds) for Ollama calls",
    )
    parser.add_argument(
        "--server-cmd",
        default=_default_server_cmd(),
        help="Shell-like command used to start the MCP server",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print exposed MCP tools then exit",
    )
    parser.add_argument(
        "--memory-path",
        default=DEFAULT_MEMORY_PATH,
        help=(
            "Path to a Markdown memory file appended to the system prompt "
            "(default: docs/mcp/memory.md)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cmd = shlex.split(args.server_cmd)
    client = McpStdioClient(cmd=cmd, cwd=ROOT, timeout_s=args.timeout)
    client.start()
    system_prompt = _build_system_prompt(args.system, args.memory_path)

    try:
        _ = client.request(
            "initialize",
            {
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "clientInfo": {"name": "ollama-mcp-bridge", "version": "0.1.0"},
            },
        )
        client.notify("notifications/initialized", {})

        if args.list_tools:
            tools_result = client.request("tools/list", {})
            tools = tools_result.get("tools", [])
            for tool in tools:
                if isinstance(tool, dict):
                    print(tool.get("name", ""))
            return 0

        if args.prompt.strip():
            answer = run_agent_once(
                client=client,
                base_url=args.base_url,
                model=args.model,
                prompt=args.prompt.strip(),
                max_steps=max(1, args.max_steps),
                timeout_s=max(5, args.timeout),
                system_prompt=system_prompt,
            )
            print(answer)
            return 0

        print("Interactive mode (type 'exit' to quit)")
        while True:
            user_prompt = input("> ").strip()
            if not user_prompt:
                continue
            if user_prompt.lower() in {"exit", "quit"}:
                break
            answer = run_agent_once(
                client=client,
                base_url=args.base_url,
                model=args.model,
                prompt=user_prompt,
                max_steps=max(1, args.max_steps),
                timeout_s=max(5, args.timeout),
                system_prompt=system_prompt,
            )
            print(answer)
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
