# backends/static/typed_data.py
"""Vue typée des sections de données d'un binaire.

CLI:
  python typed_data.py --binary <path>
                       [--section <name>]
                       [--type auto|u8|u16|u32|u64|f32|f64|str|ptr]
                       [--page <int>]

Output JSON:
  {
    "section": ".rodata", "base_addr": "0x402000", "size": 4096,
    "type": "auto", "page": 0, "page_size": 128, "total_entries": 512,
    "entries": [
      {"offset": 0,  "addr": "0x402000", "hex": "48 65 6c 6c 6f",
       "decoded": "\"Hello\"", "tag": "string"},
      {"offset": 8,  "addr": "0x402008", "hex": "00 10 40 00 00 00 00 00",
       "decoded": "0x401000", "tag": "ptr"},
      {"offset": 16, "addr": "0x402010", "hex": "01 00 00 00",
       "decoded": "1", "tag": "u32"}
    ],
    "sections": [".data", ".rodata"],
    "error": null
  }
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backends.static.structs import compute_struct_layout, load_struct_store

try:
    import lief
    _LIEF_AVAILABLE = True
except ImportError:
    lief = None
    _LIEF_AVAILABLE = False

_EXEC_SECTION_NAMES = {".text", ".init", ".fini", ".plt", ".plt.got", ".plt.sec", "__text"}
_SHF_EXECINSTR = 0x4


def _parse_int_literal(value, default: int = 0) -> int:
    try:
        return int(str(value), 0)
    except Exception:
        return default


def _is_data_section(section) -> bool:
    name = getattr(section, "name", "")
    if name in _EXEC_SECTION_NAMES:
        return False
    try:
        if section.flags & _SHF_EXECINSTR:
            return False
    except Exception:
        pass
    return True


def _get_sections(binary) -> list[str]:
    try:
        return [s.name for s in binary.sections if _is_data_section(s)]
    except Exception:
        return []


def _get_section_entry(binary, section_name: str):
    try:
        return next((s for s in binary.sections if s.name == section_name), None)
    except Exception:
        return None


def _get_section_data(binary, section_name: str) -> tuple[bytes, int] | tuple[None, None]:
    try:
        section = _get_section_entry(binary, section_name)
        if section is None:
            return None, None
        return bytes(section.content), section.virtual_address
    except Exception:
        return None, None


def _raw_data_result(
    binary_path: str,
    section_name: str | None,
    type_: str,
    page: int,
    page_size: int,
    struct_entries: list[dict],
    raw_base_addr: int | str | None = None,
) -> dict | None:
    if section_name not in (None, "", "raw"):
        return None
    try:
        data = open(binary_path, "rb").read()
    except Exception as exc:
        return {"error": str(exc), "entries": [], "sections": ["raw"], "structs": struct_entries}

    base = _parse_int_literal(raw_base_addr, 0)
    ptr_size = 8
    if type_ == "auto":
        entries, total = _decode_auto(data, base, page, page_size, ptr_size)
    elif type_ in _DECODERS:
        entries, total = _decode_typed(data, base, type_, page, page_size)
    elif type_ == "str":
        strings = _scan_strings(data, 4)
        all_str = [
            {"offset": s, "addr": hex(base + s),
             "hex": _hex_bytes(data[s:e]), "decoded": f'"{v}"', "tag": "string"}
            for s, e, v in strings
        ]
        total = len(all_str)
        entries = all_str[page * page_size:(page + 1) * page_size]
    elif type_ == "ptr":
        ptrs = _scan_pointers(data, base, len(data) + 0x10000000, ptr_size)
        all_ptr = [
            {"offset": off, "addr": hex(base + off),
             "hex": _hex_bytes(data[off:off + ptr_size]),
             "decoded": hex(v), "tag": "ptr"}
            for off, v in ptrs
        ]
        total = len(all_ptr)
        entries = all_ptr[page * page_size:(page + 1) * page_size]
    else:
        return {"error": f"Type inconnu : {type_}", "section": "raw",
                "base_addr": "0x0", "size": len(data), "type": type_, "total_entries": 0,
                "entries": [], "sections": ["raw"], "structs": struct_entries,
                "page": page, "page_size": page_size}

    return {
        "section": "raw",
        "base_addr": "0x0",
        "size": len(data),
        "type": type_,
        "page": page,
        "page_size": page_size,
        "total_entries": total,
        "entries": entries,
        "sections": ["raw"],
        "structs": struct_entries,
        "error": None,
        "source": "raw",
    }


def _resolve_struct_location(
    binary,
    requested_section: str | None,
    struct_offset: int,
    struct_addr: int | None,
) -> tuple[str | None, int]:
    if struct_addr is None:
        return requested_section, struct_offset

    try:
        addr = int(struct_addr)
    except Exception as exc:
        raise ValueError(f"Adresse de struct invalide: {struct_addr}") from exc

    if requested_section:
        candidates = [_get_section_entry(binary, requested_section)]
    else:
        try:
            candidates = [section for section in binary.sections if _is_data_section(section)]
        except Exception:
            candidates = []

    for section in candidates:
        if section is None:
            continue
        try:
            data = bytes(section.content)
            base = int(getattr(section, "virtual_address", 0) or 0)
        except Exception:
            continue
        if not data:
            continue
        if base <= addr < base + len(data):
            return str(getattr(section, "name", "") or requested_section or ""), addr - base

    if requested_section:
        raise ValueError(
            f"Adresse {hex(addr)} hors de la section {requested_section} ou section non décodable."
        )
    raise ValueError(f"Adresse {hex(addr)} hors des sections de données disponibles.")


def _hex_bytes(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)


def _decode_u8(data: bytes, i: int) -> tuple[str, str]:
    return str(data[i]), "u8"

def _decode_u16(data: bytes, i: int) -> tuple[str, str]:
    return str(int.from_bytes(data[i:i + 2], "little")), "u16"

def _decode_u32(data: bytes, i: int) -> tuple[str, str]:
    return str(int.from_bytes(data[i:i + 4], "little")), "u32"

def _decode_u64(data: bytes, i: int) -> tuple[str, str]:
    return str(int.from_bytes(data[i:i + 8], "little")), "u64"

def _decode_f32(data: bytes, i: int) -> tuple[str, str]:
    return f"{struct.unpack_from('<f', data, i)[0]:.6g}", "f32"

def _decode_f64(data: bytes, i: int) -> tuple[str, str]:
    return f"{struct.unpack_from('<d', data, i)[0]:.10g}", "f64"


_DECODERS: dict[str, tuple[int, object]] = {
    "u8": (1, _decode_u8), "u16": (2, _decode_u16),
    "u32": (4, _decode_u32), "u64": (8, _decode_u64),
    "f32": (4, _decode_f32), "f64": (8, _decode_f64),
}

_SIGNED_TAGS = {"i8", "i16", "i32", "i64", "isize"}
_UNSIGNED_TAGS = {"u8", "u16", "u32", "u64", "usize", "bool", "enum"}
_FLOAT_TAGS = {"f32", "f64"}


def _decode_typed(data: bytes, base: int, type_: str, page: int,
                  page_size: int) -> tuple[list[dict], int]:
    size, decode_fn = _DECODERS[type_]
    max_items = len(data) // size
    start = page * page_size
    entries = []
    for i in range(start, min(start + page_size, max_items)):
        off = i * size
        decoded, tag = decode_fn(data, off)
        entries.append({
            "offset": off, "addr": hex(base + off),
            "hex": _hex_bytes(data[off:off + size]),
            "decoded": decoded, "tag": tag,
        })
    return entries, max_items


def _scan_strings(data: bytes, min_len: int = 4) -> list[tuple[int, int, str]]:
    result, pos, n = [], 0, len(data)
    while pos < n:
        start, chars = pos, []
        while pos < n and 0x20 <= data[pos] < 0x7F:
            chars.append(chr(data[pos]))
            pos += 1
        if len(chars) >= min_len and (pos >= n or data[pos] == 0):
            result.append((start, pos, "".join(chars)))
        elif pos < n:
            pos += 1
    return result


def _scan_pointers(data: bytes, base: int, binary_end: int,
                   ptr_size: int) -> list[tuple[int, int]]:
    result = []
    for i in range(0, len(data) - ptr_size + 1, ptr_size):
        v = int.from_bytes(data[i:i + ptr_size], "little")
        if 0x1000 <= v < binary_end and v % 4 == 0:
            result.append((i, v))
    return result


def _decode_auto(data: bytes, base: int, page: int, page_size: int,
                 ptr_size: int = 8) -> tuple[list[dict], int]:
    binary_end = base + len(data) + 0x10000000
    covered: set[int] = set()
    all_entries: list[dict] = []

    for start, end, val in _scan_strings(data, 4):
        span = set(range(start, end + 1))
        if not span & covered:
            all_entries.append({
                "offset": start, "addr": hex(base + start),
                "hex": _hex_bytes(data[start:min(end, start + 16)]),
                "decoded": f'"{val[:80]}"', "tag": "string",
            })
            covered.update(span)

    for off, v in _scan_pointers(data, base, binary_end, ptr_size):
        if off not in covered:
            all_entries.append({
                "offset": off, "addr": hex(base + off),
                "hex": _hex_bytes(data[off:off + ptr_size]),
                "decoded": hex(v), "tag": "ptr",
            })
            covered.update(range(off, off + ptr_size))

    pos = 0
    while pos < len(data):
        if pos not in covered:
            if pos + 4 <= len(data):
                v = int.from_bytes(data[pos:pos + 4], "little")
                all_entries.append({
                    "offset": pos, "addr": hex(base + pos),
                    "hex": _hex_bytes(data[pos:pos + 4]),
                    "decoded": str(v), "tag": "u32",
                })
                pos += 4
            else:
                all_entries.append({
                    "offset": pos, "addr": hex(base + pos),
                    "hex": f"{data[pos]:02x}",
                    "decoded": str(data[pos]), "tag": "u8",
                })
                pos += 1
        else:
            pos += 1

    all_entries.sort(key=lambda e: e["offset"])
    start_idx = page * page_size
    return all_entries[start_idx:start_idx + page_size], len(all_entries)


def _decode_struct_scalar(data: bytes, tag: str, ptr_size: int) -> tuple[str, str]:
    if tag == "char":
        if not data:
            return "''", "char"
        value = data[0]
        decoded = chr(value) if 0x20 <= value < 0x7F else f"\\x{value:02x}"
        return repr(decoded), "char"
    if tag == "ptr":
        return hex(int.from_bytes(data, "little")), "ptr"
    if tag in _FLOAT_TAGS:
        if tag == "f32":
            padded = data[:4].ljust(4, bytes(1))
            return f"{struct.unpack_from('<f', padded, 0)[0]:.6g}", "f32"
        padded = data[:8].ljust(8, bytes(1))
        return f"{struct.unpack_from('<d', padded, 0)[0]:.10g}", "f64"
    if tag in _SIGNED_TAGS:
        return str(int.from_bytes(data, "little", signed=True)), tag
    if tag in _UNSIGNED_TAGS:
        return str(int.from_bytes(data, "little", signed=False)), tag
    return _hex_bytes(data), tag


def _format_enum_value(field: dict, raw_value: int) -> str:
    enum_values = field.get("enum_values") or []
    exact = next((entry for entry in enum_values if int(entry.get("value", 0)) == raw_value), None)
    if exact:
        return f"{exact.get('name')} ({raw_value})"
    if raw_value > 0:
        remaining = raw_value
        labels: list[str] = []
        for entry in sorted(enum_values, key=lambda item: int(item.get("value", 0))):
            value = int(entry.get("value", 0))
            if value <= 0:
                continue
            if remaining & value == value:
                labels.append(str(entry.get("name") or value))
                remaining &= ~value
        if labels and remaining == 0:
            return f"{' | '.join(labels)} ({raw_value})"
    return str(raw_value)


def _decode_compound_value(
    field: dict,
    blob: bytes,
    ptr_size: int,
    definitions: dict,
    depth: int,
) -> tuple[str, str]:
    if depth >= 1:
        return f"{field['type_kind']} {field['type']} ({field['size']} bytes)", str(field["type_kind"])

    layout = compute_struct_layout(definitions, field["type"], ptr_size)
    preview_fields = []
    visible_fields = (layout.get("fields") or [])[:4]
    for nested_field in visible_fields:
        start = int(nested_field.get("offset") or 0)
        end = start + int(nested_field.get("size") or 0)
        decoded, _ = _decode_struct_field_value(nested_field, blob[start:end], ptr_size, definitions, depth + 1)
        preview_fields.append(f"{nested_field.get('name')}={decoded}")
    suffix = ", ..." if len((layout.get("fields") or [])) > len(visible_fields) else ""
    return f"{layout.get('kind')} {field['type']} {{ " + ", ".join(preview_fields) + suffix + " }", str(layout.get("kind") or field["type_kind"])


def _decode_struct_field_value(field: dict, blob: bytes, ptr_size: int, definitions: dict, depth: int = 0) -> tuple[str, str]:
    if field["type_kind"] in {"struct", "union"}:
        return _decode_compound_value(field, blob, ptr_size, definitions, depth)

    if field["type_kind"] == "enum":
        if field["array_len"]:
            values = []
            for index in range(field["array_len"]):
                start = index * field["elem_size"]
                end = start + field["elem_size"]
                raw_value = int.from_bytes(blob[start:end], "little", signed=False)
                values.append(_format_enum_value(field, raw_value))
            preview = ", ".join(values[:8])
            if len(values) > 8:
                preview += ", ..."
            return f"[{preview}]", "enum"
        raw_value = int.from_bytes(blob[: field["size"]], "little", signed=False)
        return _format_enum_value(field, raw_value), "enum"

    if field["array_len"]:
        if field["tag"] == "char":
            text = blob.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            return f'"{text}"', "string"
        values = []
        for index in range(field["array_len"]):
            start = index * field["elem_size"]
            end = start + field["elem_size"]
            scalar, _ = _decode_struct_scalar(blob[start:end], field["tag"], ptr_size)
            values.append(scalar)
        preview = ", ".join(values[:8])
        if len(values) > 8:
            preview += ", ..."
        return f"[{preview}]", "array"

    return _decode_struct_scalar(blob, field["tag"], ptr_size)


def _decode_struct_entries(
    data: bytes,
    base: int,
    struct_name: str,
    struct_offset: int,
    ptr_size: int,
    definitions: dict,
) -> dict:
    layout = compute_struct_layout(definitions, struct_name, ptr_size)
    if struct_offset < 0:
        raise ValueError("Offset de struct négatif.")
    if struct_offset + layout["size"] > len(data):
        raise ValueError(
            f"La struct {struct_name} déborde de la section sélectionnée "
            f"(offset 0x{struct_offset:x}, taille {layout['size']})."
        )

    fields = []
    for field in layout["fields"]:
        start = struct_offset + field["offset"]
        end = start + field["size"]
        chunk = data[start:end]
        decoded, tag = _decode_struct_field_value(field, chunk, ptr_size, definitions)
        fields.append({
            "field_name": field["name"],
            "field_type": field["display_type"],
            "field_kind": field["type_kind"],
            "offset": field["offset"],
            "absolute_offset": start,
            "addr": hex(base + start),
            "hex": _hex_bytes(chunk),
            "decoded": decoded,
            "tag": tag,
            "size": field["size"],
        })
    return {
        "name": struct_name,
        "kind": layout.get("kind") or "struct",
        "offset": struct_offset,
        "addr": hex(base + struct_offset),
        "size": layout["size"],
        "align": layout["align"],
        "fields": fields,
    }


def get_typed_data(
    binary_path: str,
    section_name: str | None = None,
    type_: str = "auto",
    page: int = 0,
    page_size: int = 128,
    struct_name: str | None = None,
    struct_offset: int = 0,
    struct_addr: int | None = None,
    raw_base_addr: int | str | None = None,
) -> dict:
    struct_store = load_struct_store()
    struct_entries = [
        {
            "name": name,
            "kind": str((definition or {}).get("kind") or "struct"),
            "field_count": len((definition or {}).get("fields") or []),
        }
        for name, definition in sorted((struct_store.get("definitions") or {}).items())
        if str((definition or {}).get("kind") or "struct") in {"struct", "union"}
    ]
    if not os.path.isfile(binary_path):
        return {"error": f"Fichier introuvable : {binary_path}", "entries": [], "sections": [], "structs": struct_entries}
    if not _LIEF_AVAILABLE:
        raw_result = _raw_data_result(binary_path, section_name, type_, page, page_size, struct_entries, raw_base_addr)
        return raw_result or {"error": "lief non disponible", "entries": [], "sections": ["raw"], "structs": struct_entries}

    binary = lief.parse(binary_path)
    if binary is None:
        raw_result = _raw_data_result(binary_path, section_name, type_, page, page_size, struct_entries, raw_base_addr)
        return raw_result or {"error": "Parsing échoué", "entries": [], "sections": ["raw"], "structs": struct_entries}

    all_sections = _get_sections(binary)
    if not all_sections:
        return {"section": None, "base_addr": "0x0", "size": 0, "type": type_,
                "entries": [], "sections": [], "total_entries": 0,
                "page": page, "page_size": page_size, "error": None, "structs": struct_entries}

    target = section_name if section_name in all_sections else all_sections[0]
    if struct_name:
        try:
            resolved_section, resolved_offset = _resolve_struct_location(
                binary,
                target if target in all_sections else section_name,
                struct_offset,
                struct_addr,
            )
        except Exception as exc:
            return {
                "error": str(exc),
                "section": target,
                "base_addr": "0x0",
                "size": 0,
                "type": "compound",
                "entries": [],
                "sections": all_sections,
                "structs": struct_entries,
                "page": 0,
                "page_size": page_size,
                "total_entries": 0,
            }
        if resolved_section:
            target = resolved_section
        struct_offset = resolved_offset
    data, base = _get_section_data(binary, target)
    if data is None:
        return {"error": f"Section introuvable : {target}", "section": target,
                "base_addr": "0x0", "size": 0, "type": type_, "total_entries": 0,
                "entries": [], "sections": all_sections, "structs": struct_entries,
                "page": page, "page_size": page_size}
    if len(data) == 0:
        return {
            "section": target, "base_addr": hex(base or 0), "size": 0, "type": type_,
            "page": page, "page_size": page_size, "total_entries": 0,
            "entries": [], "sections": all_sections, "error": "Section vide (BSS)", "structs": struct_entries,
        }

    try:
        is_64 = getattr(getattr(binary, "header", None), "is_64", True)
    except Exception:
        is_64 = True
    ptr_size = 8 if is_64 else 4

    if struct_name:
        try:
            applied = _decode_struct_entries(
                data,
                base or 0,
                struct_name,
                struct_offset,
                ptr_size,
                struct_store["definitions"],
            )
        except Exception as exc:
            return {
                "error": str(exc),
                "section": target,
                "base_addr": hex(base or 0),
                "size": len(data),
                "type": "compound",
                "entries": [],
                "sections": all_sections,
                "structs": struct_entries,
                "page": 0,
                "page_size": page_size,
                "total_entries": 0,
            }
        return {
            "section": target,
            "base_addr": hex(base or 0),
            "size": len(data),
            "type": "compound",
            "page": 0,
            "page_size": page_size,
            "total_entries": len(applied["fields"]),
            "entries": applied["fields"],
            "sections": all_sections,
            "structs": struct_entries,
            "applied_struct": {**applied, "section": target},
            "error": None,
        }

    if type_ == "auto":
        entries, total = _decode_auto(data, base or 0, page, page_size, ptr_size)
    elif type_ in _DECODERS:
        entries, total = _decode_typed(data, base or 0, type_, page, page_size)
    elif type_ == "str":
        strings = _scan_strings(data, 4)
        all_str = [
            {"offset": s, "addr": hex((base or 0) + s),
             "hex": _hex_bytes(data[s:e]), "decoded": f'"{v}"', "tag": "string"}
            for s, e, v in strings
        ]
        total = len(all_str)
        entries = all_str[page * page_size:(page + 1) * page_size]
    elif type_ == "ptr":
        binary_end = (base or 0) + len(data) + 0x10000000
        ptrs = _scan_pointers(data, base or 0, binary_end, ptr_size)
        all_ptr = [
            {"offset": off, "addr": hex((base or 0) + off),
             "hex": _hex_bytes(data[off:off + ptr_size]),
             "decoded": hex(v), "tag": "ptr"}
            for off, v in ptrs
        ]
        total = len(all_ptr)
        entries = all_ptr[page * page_size:(page + 1) * page_size]
    else:
        return {"error": f"Type inconnu : {type_}", "section": target,
                "base_addr": hex(base or 0), "size": len(data), "type": type_, "total_entries": 0,
                "entries": [], "sections": all_sections, "structs": struct_entries,
                "page": page, "page_size": page_size}

    return {
        "section": target, "base_addr": hex(base or 0), "size": len(data),
        "type": type_, "page": page, "page_size": page_size, "total_entries": total,
        "entries": entries, "sections": all_sections, "structs": struct_entries, "error": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Typed data view for binary sections")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--section", default=None)
    parser.add_argument("--type", default="auto", dest="type_")
    parser.add_argument("--page", type=int, default=0)
    parser.add_argument("--struct-name", default=None)
    parser.add_argument("--struct-offset", default="0x0")
    parser.add_argument("--struct-addr", default=None)
    parser.add_argument("--raw-base-addr", default=None)
    args = parser.parse_args()
    try:
        struct_offset = int(str(args.struct_offset), 0)
    except Exception:
        struct_offset = 0
    try:
        struct_addr = int(str(args.struct_addr), 0) if args.struct_addr is not None else None
    except Exception:
        struct_addr = None
    print(
        json.dumps(
            get_typed_data(
                args.binary,
                args.section,
                args.type_,
                args.page,
                struct_name=args.struct_name,
                struct_offset=struct_offset,
                struct_addr=struct_addr,
                raw_base_addr=args.raw_base_addr,
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
