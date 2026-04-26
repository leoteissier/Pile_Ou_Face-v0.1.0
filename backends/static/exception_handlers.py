# backends/static/exception_handlers.py
"""Extraction des gestionnaires d'exceptions (PE SEH, ELF DWARF, Mach-O).

CLI:
  python exception_handlers.py --binary <path>

Output JSON:
  {
    "format": "PE",
    "arch": "x86_64",
    "entries": [
      {"func_start": "0x1000", "func_end": "0x1100",
       "handler": "0x2000", "handler_type": "SEH", "unwind_flags": []}
    ],
    "count": N,
    "error": null
  }
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import lief
    _LIEF_AVAILABLE = True
except ImportError:
    lief = None
    _LIEF_AVAILABLE = False


def _arch_name(binary) -> str:
    try:
        return binary.header.machine.name
    except Exception:
        try:
            return str(binary.header.cpu_type)
        except Exception:
            return "unknown"


def _pe_exceptions(binary) -> list[dict]:
    entries = []
    imgbase = getattr(getattr(binary, "optional_header", None), "imagebase", 0) or 0
    try:
        for exc in binary.exceptions:
            start = getattr(exc, "rva_start", 0) or 0
            end = getattr(exc, "rva_end", 0) or 0
            entry: dict = {
                "func_start": hex(start + imgbase),
                "func_end": hex(end + imgbase),
                "handler": None,
                "handler_type": "SEH",
                "unwind_flags": [],
            }
            try:
                ui = exc.unwind_info
                uw_flags = getattr(ui, "flags", 0) or 0
                flags = []
                if uw_flags & 0x1:
                    flags.append("EXCEPTION")
                if uw_flags & 0x2:
                    flags.append("TERMINATION")
                if uw_flags & 0x4:
                    flags.append("CHAININFO")
                entry["unwind_flags"] = flags
                handler_rva = getattr(ui, "exception_handler", None)
                if handler_rva:
                    entry["handler"] = hex(handler_rva + imgbase)
                    if "EXCEPTION" in flags:
                        entry["handler_type"] = "C++ EH"
            except Exception:
                pass
            entries.append(entry)
    except (AttributeError, Exception):
        pass

    if not entries:
        try:
            lc = binary.load_configuration
            for handler_rva in lc.se_handler_table:
                entries.append({
                    "func_start": None,
                    "func_end": None,
                    "handler": hex(handler_rva + imgbase),
                    "handler_type": "SEH",
                    "unwind_flags": [],
                })
        except Exception:
            pass
    return entries


def _elf_dwarf_exceptions(binary) -> list[dict]:
    entries = []
    try:
        eh_section = next(
            (s for s in binary.sections if s.name in (".eh_frame", "__eh_frame")),
            None,
        )
        if eh_section is None:
            return []
        data = bytes(eh_section.content)
        base_addr = eh_section.virtual_address
        pos = 0
        while pos + 8 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "little")
            if length == 0:
                break
            if length == 0xFFFFFFFF:
                # 64-bit DWARF extension — skip; not supported
                break
            cie_id = int.from_bytes(data[pos + 4:pos + 8], "little")
            is_fde = cie_id != 0 and cie_id != 0xFFFFFFFF
            if is_fde and pos + 16 <= len(data):
                try:
                    pc_offset = int.from_bytes(data[pos + 8:pos + 12], "little", signed=True)
                    pc_range = int.from_bytes(data[pos + 12:pos + 16], "little")
                    pc_begin = base_addr + pos + 8 + pc_offset
                    entries.append({
                        "func_start": hex(pc_begin),
                        "func_end": hex(pc_begin + pc_range),
                        "handler": None,
                        "handler_type": "DWARF FDE",
                        "unwind_flags": [],
                    })
                except Exception:
                    pass
            pos += 4 + length
    except Exception:
        pass
    return entries


def _macho_exceptions(binary) -> list[dict]:
    entries = []
    try:
        for section in binary.sections:
            if section.name in ("__eh_frame", "__unwind_info"):
                entries.append({
                    "func_start": None,
                    "func_end": None,
                    "handler": None,
                    "handler_type": "C++ EH (Mach-O)",
                    "unwind_flags": [f"{section.name} present"],
                })
    except Exception:
        pass
    return entries


def get_exception_handlers(binary_path: str) -> dict:
    if not _LIEF_AVAILABLE:
        return {"error": "lief non disponible", "format": "unknown", "arch": "unknown", "entries": [], "count": 0}
    if not os.path.isfile(binary_path):
        return {"error": f"Fichier introuvable : {binary_path}", "format": "unknown", "arch": "unknown", "entries": [], "count": 0}

    binary = lief.parse(binary_path)
    if binary is None:
        return {"error": "Parsing échoué", "format": "unknown", "arch": "unknown", "entries": [], "count": 0}

    fmt, arch, entries = "unknown", "unknown", []
    if isinstance(binary, lief.PE.Binary):
        fmt, arch = "PE", _arch_name(binary)
        entries = _pe_exceptions(binary)
    elif isinstance(binary, lief.ELF.Binary):
        fmt, arch = "ELF", _arch_name(binary)
        entries = _elf_dwarf_exceptions(binary)
    elif hasattr(lief, "MachO") and isinstance(binary, lief.MachO.Binary):
        fmt, arch = "MachO", _arch_name(binary)
        entries = _macho_exceptions(binary)

    return {"format": fmt, "arch": arch, "entries": entries, "count": len(entries), "error": None}


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract exception handlers")
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(get_exception_handlers(args.binary), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
