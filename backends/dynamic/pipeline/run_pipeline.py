#!/usr/bin/env python3
"""Lance la pipeline dynamique et genere output.json.

Orchestration trace runtime, disasm optionnel, et payload unifie.
Voir backends/dynamic/README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import subprocess
import shutil
import re
from typing import List, Optional

# ROOT: backends/dynamic/pipeline/ -> project root (three levels up)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backends.dynamic.core.interfaces import ExecutionEngine, TraceConfigLike
from backends.dynamic.pipeline.stack_model import build_dynamic_analysis
from backends.static.disasm import disassemble_with_capstone

try:
    from backends.static.symbols import extract_symbols
except Exception:
    extract_symbols = None


def _default_engine() -> ExecutionEngine:
    from backends.dynamic.engine.unicorn import create_engine

    return create_engine()


def _expand_payload_expression(text: Optional[str]) -> str:
    if text is None:
        return ""
    value = text.strip()
    if not value:
        return ""
    if "+" not in value and "*" not in value:
        return value
    parts = [p.strip() for p in value.split("+") if p.strip()]
    out: List[str] = []
    for part in parts:
        m = re.match(r"^(.+?)\*(\d+)$", part)
        if m:
            out.append(m.group(1) * int(m.group(2)))
        else:
            out.append(part)
    return "".join(out)


def _normalize_path(path: str) -> str:
    cwd = os.getcwd()
    if path.startswith(cwd + os.sep):
        return os.path.relpath(path, cwd)
    return path


def _load_binary(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _load_function_symbols(binary_path: str) -> list[dict]:
    if extract_symbols is None:
        return []
    try:
        raw = extract_symbols(binary_path, defined_only=True)
    except Exception:
        return []
    out = []
    for symbol in raw if isinstance(raw, list) else []:
        if str(symbol.get("type") or "").lower() != "t":
            continue
        addr = str(symbol.get("addr") or "").strip()
        if not addr or addr == "0x0":
            continue
        out.append(
            {
                "name": str(symbol.get("name") or "").strip(),
                "addr": addr,
                "size": symbol.get("size"),
                "type": str(symbol.get("type") or "T"),
            }
        )
    return out


def run_pipeline(
    binary_path: str,
    source_path: Optional[str],
    config: TraceConfigLike,
    output_path: Optional[str],
    engine: Optional[ExecutionEngine] = None,
) -> dict:
    code = _load_binary(binary_path)
    runtime = engine if engine is not None else _default_engine()
    trace = runtime.trace_binary(code, config, binary_path)
    risks: List[dict] = []
    disasm = None
    if output_path:
        disasm_path = _derive_disasm_path(output_path)
        disasm = _build_disasm(binary_path, output_path=disasm_path)
    meta = {
        **trace.get("meta", {}),
        "dynamic_model_version": 2,
        "binary": _normalize_path(binary_path),
        "source": _normalize_path(source_path) if source_path else None,
        "functions": _load_function_symbols(binary_path),
        "disasm_path": os.path.abspath(disasm.get("path")) if disasm else None,
        "disasm": disasm.get("lines") if disasm else None,
    }
    analysis_by_step = build_dynamic_analysis(
        trace.get("snapshots", []),
        meta,
        binary_path,
        disasm_lines=disasm.get("lines") if disasm else None,
    )
    return {
        "snapshots": trace.get("snapshots", []),
        "risks": risks,
        "analysisByStep": analysis_by_step,
        "meta": meta,
    }


def _build_disasm(binary_path: str, output_path: str) -> dict | None:
    structured = _build_disasm_with_capstone(binary_path, output_path)
    if structured is not None:
        return structured
    return _build_disasm_with_objdump(binary_path, output_path)


def _build_disasm_with_capstone(binary_path: str, output_path: str) -> dict | None:
    try:
        lines = disassemble_with_capstone(binary_path)
    except Exception:
        return None
    if not isinstance(lines, list) or not lines:
        return None

    rendered_lines = []
    output_lines = []
    for idx, entry in enumerate(lines, start=1):
        if not isinstance(entry, dict):
            continue
        addr = str(entry.get("addr") or "").strip().lower()
        if not addr:
            continue
        addr_text = addr[2:] if addr.startswith("0x") else addr
        bytes_text = str(entry.get("bytes") or "").strip()
        mnemonic = str(entry.get("mnemonic") or "").strip()
        operands = str(entry.get("operands") or "").strip()
        asm_text = f"{mnemonic} {operands}".strip()
        raw = f"{addr_text}:\t{bytes_text}\t{asm_text}".rstrip()
        output_lines.append(raw)
        rendered_lines.append(
            {
                "addr": addr,
                "text": str(entry.get("text") or asm_text),
                "raw": raw,
                "bytes": bytes_text,
                "mnemonic": mnemonic,
                "operands": operands,
                "line": idx,
            }
        )

    if not rendered_lines:
        return None
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(output_lines) + "\n")
    return {"path": output_path, "lines": rendered_lines}


def _build_disasm_with_objdump(binary_path: str, output_path: str) -> dict | None:
    if not shutil.which("objdump"):
        return None
    try:
        result = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    lines = []
    for idx, line in enumerate(result.stdout.splitlines(), start=1):
        match = re.match(r"^\s*([0-9a-fA-F]+):\s*(.*)$", line)
        if not match:
            continue
        addr = f"0x{match.group(1).lower()}"
        text_line = match.group(2).strip()
        lines.append({"addr": addr, "text": text_line, "raw": line, "line": idx})
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(result.stdout)
    return {"path": output_path, "lines": lines}


def _derive_disasm_path(output_path: str) -> str:
    if output_path.endswith(".json"):
        return output_path[: -len(".json")] + ".disasm.asm"
    return output_path + ".disasm.asm"


def _main(argv: Optional[List[str]] = None) -> int:
    from backends.dynamic.engine.unicorn.config import TraceConfig

    parser = argparse.ArgumentParser(description="Generate a trace JSON with Unicorn")
    parser.add_argument("--binary", required=True, help="Raw x86_64 binary")
    parser.add_argument("--output", default="output.json", help="Output JSON path")
    parser.add_argument(
        "--base", default="0x400000", help="Base address for raw/PIE binaries"
    )
    parser.add_argument("--stack-base", default="0x7ffffffde000", help="Stack base")
    parser.add_argument(
        "--stack-size", type=int, default=0x20000, help="Stack size bytes"
    )
    parser.add_argument("--max-steps", type=int, default=200, help="Max instructions")
    parser.add_argument("--stack-entries", type=int, default=24, help="Stack entries")
    parser.add_argument(
        "--arch-bits", type=int, default=64, choices=[32, 64], help="Architecture bits"
    )
    parser.add_argument(
        "--start-interp", action="store_true", help="Start at ELF interpreter"
    )
    parser.add_argument("--stdin", default="", help="Inject data for read(0, ...)")
    parser.add_argument("--stdin-hex", default=None, help="Inject raw bytes (hex)")
    parser.add_argument(
        "--buffer-offset", type=int, default=None, help="Buffer offset from RBP"
    )
    parser.add_argument(
        "--buffer-size", type=int, default=0, help="Buffer size in bytes"
    )
    parser.add_argument(
        "--start-symbol", default=None, help="Start at symbol (e.g. main)"
    )
    parser.add_argument("--stop-symbol", default=None, help="Stop at symbol")
    parser.add_argument(
        "--no-capture-binary", action="store_true", help="Capture outside binary"
    )
    parser.add_argument("--argv1", default=None, help="Set argv[1]")
    parser.add_argument("--patch-at-rip", default=None, metavar="HEX")
    parser.add_argument("--patch-rbp-offset", default=None, metavar="INT")
    parser.add_argument("--patch-value", default=None, metavar="HEX")
    parser.add_argument("--patch-payload", default=None, metavar="HEX")
    parser.add_argument("--inject-at-start", action="store_true")
    args = parser.parse_args(argv)

    stdin_text = _expand_payload_expression(args.stdin)
    stdin_data = stdin_text.encode("utf-8", errors="ignore")
    if args.stdin_hex:
        cleaned = args.stdin_hex.replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        try:
            stdin_data = bytes.fromhex(cleaned)
        except ValueError:
            raise SystemExit("Invalid --stdin-hex")

    memory_patches = None
    stack_payload = None
    if (
        args.inject_at_start
        and args.patch_rbp_offset is not None
        and args.patch_payload is not None
    ):
        offset = int(args.patch_rbp_offset, 0)
        cleaned = args.patch_payload.strip().replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        payload_bytes = bytes.fromhex(cleaned)
        stack_payload = (offset, payload_bytes)
    elif args.patch_at_rip is not None and args.patch_rbp_offset is not None:
        rip = int(args.patch_at_rip, 16)
        offset = int(args.patch_rbp_offset, 0)
        if args.patch_payload is not None:
            cleaned = args.patch_payload.strip().replace(" ", "").replace("\n", "")
            if cleaned.startswith("0x"):
                cleaned = cleaned[2:]
            payload_bytes = bytes.fromhex(cleaned)
            memory_patches = [(rip, offset, payload_bytes)]
        elif args.patch_value is not None:
            val = int(args.patch_value, 16)
            if val < 0 or val > 0xFFFFFFFF:
                val = val & 0xFFFFFFFF
            memory_patches = [(rip, offset, val)]

    config = TraceConfig(
        base=int(args.base, 16),
        stack_base=int(args.stack_base, 16),
        stack_size=args.stack_size,
        max_steps=args.max_steps,
        stack_entries=args.stack_entries,
        arch_bits=args.arch_bits,
        interp_base=0x70000000 if args.arch_bits == 32 else 0x7F0000000000,
        start_interp=args.start_interp,
        stdin_data=stdin_data,
        buffer_offset=args.buffer_offset,
        buffer_size=args.buffer_size,
        start_symbol=args.start_symbol,
        stop_symbol=args.stop_symbol,
        argv1=(
            _expand_payload_expression(args.argv1) if args.argv1 is not None else None
        ),
        capture_start_addr=None,
        loader_max_steps=None,
        capture_ranges=None if args.no_capture_binary else [],
        stop_addr=None,
        memory_patches=memory_patches,
        stack_payload=stack_payload,
    )

    payload = run_pipeline(args.binary, None, config, args.output)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
