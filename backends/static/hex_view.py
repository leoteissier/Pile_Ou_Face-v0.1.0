"""Hex View — dump hexadecimal d'un binaire avec metadonnees de sections."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running as a script directly (not only via `python -m`)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import lief
except ImportError:
    lief = None

from backends.shared.log import configure_logging, get_logger, make_meta

logger = get_logger(__name__)
BYTES_PER_ROW = 16


def _section_type(name: str) -> str:
    if name in (".text", "__text", "CODE"):
        return "code"
    if name in (".data", "__data", ".rodata", "__const", ".rdata", ".idata", ".edata"):
        return "data"
    if name in (".bss", "__bss"):
        return "bss"
    return "other"


def _get_sections(binary_path: str) -> list[dict]:
    if not lief:
        return []
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return []
    except Exception:
        return []

    sections = []
    src = []
    if isinstance(binary, lief.ELF.Binary):
        src = [(s.name, s.file_offset, s.virtual_address, s.size) for s in binary.sections if s.size]
    elif isinstance(binary, lief.MachO.Binary):
        src = [(s.name, s.offset, s.virtual_address, s.size) for s in binary.sections if s.size]
    elif isinstance(binary, lief.PE.Binary):
        ib = binary.optional_header.imagebase
        src = [(s.name, s.offset, s.virtual_address + ib, s.size) for s in binary.sections if s.size]

    for name, offset, vaddr, size in src:
        sections.append({
            "name": name, "offset": offset, "virtual_address": vaddr,
            "size": size, "type": _section_type(name),
        })
    return sections


def hex_dump(binary_path: str, offset: int = 0, length: int = 512) -> dict:
    """Returns hexdump rows from a binary file.

    Returns:
        {rows: [{offset, hex, ascii}], sections: [...], file_size: N, meta: {...}}
    """
    path = Path(binary_path)
    if not path.exists():
        return {
            "rows": [],
            "sections": [],
            "file_size": 0,
            "meta": make_meta("hex_view"),
            "error": f"File not found: {binary_path}",
        }

    file_size = path.stat().st_size
    if offset >= file_size:
        return {
            "rows": [],
            "sections": _get_sections(binary_path),
            "file_size": file_size,
            "meta": make_meta("hex_view"),
        }

    length = min(length, file_size - offset, 65536)

    with open(path, "rb") as f:
        f.seek(offset)
        raw = f.read(length)

    rows = []
    for i in range(0, len(raw), BYTES_PER_ROW):
        chunk = raw[i : i + BYTES_PER_ROW]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(
            {
                "offset": f"0x{(offset + i):08x}",
                "hex": hex_str,
                "ascii": ascii_str,
            }
        )

    return {
        "rows": rows,
        "sections": _get_sections(binary_path),
        "file_size": file_size,
        "meta": make_meta("hex_view"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Hex View")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--length", type=int, default=512)
    args = parser.parse_args()
    configure_logging()
    print(json.dumps(hex_dump(args.binary, args.offset, args.length)))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
