"""Recherche de gadgets ROP dans les sections exécutables.

CLI:
  python rop_gadgets.py --binary <path> [--arch x86_64] [--max-insns 5]

Output JSON: [{addr, instructions, type, regs_modified}]
"""

from __future__ import annotations
import argparse, json
import re
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger
from backends.static.arch import ArchInfo, detect_binary_arch_from_path, get_feature_support, get_raw_arch_info

try:
    import lief
except ImportError:  # pragma: no cover - optional dependency
    lief = None

_log = get_logger(__name__)
_RET_BYTES = {0xC3, 0xC2}
_MAX_LOOKBACK = 20


def _scan_for_rets(data: bytes) -> list[int]:
    return [i for i, b in enumerate(data) if b in _RET_BYTES]


def _classify_gadget(instructions: list[str]) -> str:
    joined = " ".join(instructions).lower()
    if "syscall" in joined or "int 0x80" in joined:
        return "syscall"
    if any(token in joined for token in ("xchg rsp", "xchg esp", "mov sp", "add sp", "addi sp", "ldp x29, x30")):
        return "pivot"
    if instructions and re.match(r"^(pop|ldp|ldm|lw|ld|ld\.w|ld\.d)\b", instructions[0].lower()) and len(instructions) <= 3:
        return "pop_ret"
    if any(x in joined for x in ("mov [", "mov dword", "mov qword", "str ", "strb ", "stur ", "stp ", "sw ", "sd ", "sb ", "sh ", "stw ", "std ", "st.", "ld ", "ldr ", "lw ")):
        return "load_store"
    if any(x in joined for x in ("add ", "addi ", "addiu ", "daddiu ", "sub ", "xor ", "and ", "andi ", "or ", "ori ", "eor ", "mul ", "sll ", "srl ", "lsl ", "lsr ")):
        return "arithmetic"
    return "generic"


_REGISTER_PREFIXES = (
    "r",
    "e",
    "x",
    "w",
    "a",
    "t",
    "s",
    "v",
    "o",
    "i",
)


def _normalize_reg(token: str) -> str:
    cleaned = str(token or "").strip().lower()
    cleaned = cleaned.strip("{}[](),!")
    cleaned = cleaned.lstrip("$%")
    aliases = {
        "fp": "r11",
        "s0": "fp",
        "s8": "fp",
        "xzr": "zero",
        "wzr": "zero",
    }
    return aliases.get(cleaned, cleaned)


def _looks_like_reg(token: str) -> bool:
    reg = _normalize_reg(token)
    if reg in {"sp", "rsp", "esp", "rbp", "ebp", "lr", "ra", "pc", "zero"}:
        return True
    if re.fullmatch(r"(?:r|x|w|e|a|t|s|v|o|i)\d+", reg):
        return True
    if re.fullmatch(r"[re]?(?:ax|bx|cx|dx|si|di|bp|sp)", reg):
        return True
    return bool(reg and reg[0] in _REGISTER_PREFIXES and reg[1:].isdigit())


def _split_operands(text: str) -> tuple[str, list[str]]:
    parts = str(text or "").strip().split(None, 1)
    if not parts:
        return "", []
    mnemonic = parts[0].lower()
    if len(parts) == 1:
        return mnemonic, []
    operands = [part.strip() for part in parts[1].split(",") if part.strip()]
    return mnemonic, operands


def _destination_registers(instruction: str) -> list[str]:
    mnemonic, operands = _split_operands(instruction)
    if not mnemonic or not operands:
        return []

    if mnemonic == "pop":
        return [_normalize_reg(op) for op in operands if _looks_like_reg(op)]

    if mnemonic in {"ldp", "ldm", "ldmia", "ldmfd"}:
        regs: list[str] = []
        for op in operands[:2]:
            for candidate in re.findall(r"[$%]?[a-z][a-z0-9]*", op.lower()):
                normalized = _normalize_reg(candidate)
                if normalized not in {"sp", "pc"} and _looks_like_reg(normalized):
                    regs.append(normalized)
        return regs

    if mnemonic in {"xchg"} and len(operands) >= 2:
        return [_normalize_reg(op) for op in operands[:2] if _looks_like_reg(op)]

    if mnemonic in {
        "mov",
        "movzx",
        "movsx",
        "lea",
        "add",
        "addi",
        "addiu",
        "daddiu",
        "sub",
        "xor",
        "and",
        "andi",
        "or",
        "ori",
        "eor",
        "mul",
        "lsl",
        "lsr",
        "sll",
        "srl",
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsw",
        "ldur",
        "ld",
        "lw",
        "lwu",
        "lh",
        "lhu",
        "lb",
        "lbu",
        "ld.w",
        "ld.d",
    }:
        dst = operands[0]
        if "[" in dst or "(" in dst:
            return []
        reg = _normalize_reg(dst)
        return [reg] if _looks_like_reg(reg) and reg not in {"zero", "pc"} else []

    if mnemonic in {"str", "strb", "strh", "stur", "stp", "sw", "sd", "sb", "sh", "stw", "std"} or mnemonic.startswith("st."):
        return []

    return []


def _modified_registers(instructions: list[str]) -> list[str]:
    regs: list[str] = []
    seen: set[str] = set()
    for instruction in instructions:
        for reg in _destination_registers(instruction):
            if reg in seen:
                continue
            seen.add(reg)
            regs.append(reg)
    return regs


def _disasm_bytes(
    data: bytes,
    offset: int,
    length: int,
    arch: str = "x86_64",
    *,
    address: int | None = None,
) -> list[str]:
    try:
        import capstone

        info = get_raw_arch_info(arch)
        if info is None or info.capstone_tuple is None:
            return []
        md = capstone.Cs(*info.capstone_tuple)
        segment = data[offset : offset + length]
        return [f"{i.mnemonic} {i.op_str}".strip() for i in md.disasm(segment, offset if address is None else address)]
    except ImportError:
        return []
    except Exception:
        return []


def _find_x86_gadgets(
    data: bytes,
    arch_name: str,
    max_insns: int,
    support: Any,
    *,
    base_addr: int = 0,
) -> list[dict[str, Any]]:
    gadgets: list[dict[str, Any]] = []
    seen: set[str] = set()

    for ret_off in _scan_for_rets(data):
        for lookback in range(1, min(_MAX_LOOKBACK, ret_off) + 1):
            start = ret_off - lookback
            insns = _disasm_bytes(
                data,
                start,
                lookback + 1,
                arch_name,
                address=base_addr + start,
            )
            if not insns:
                continue
            if not insns[-1].startswith("ret"):
                continue
            if len(insns) > max_insns:
                continue
            key = "|".join(insns)
            if key in seen:
                continue
            seen.add(key)
            gadgets.append(
                {
                    "addr": hex(base_addr + start),
                    "instructions": insns,
                    "type": _classify_gadget(insns),
                    "regs_modified": _modified_registers(insns),
                    "support_level": support.level,
                    "support_note": support.note,
                }
            )
            break

    return gadgets


def _is_return_instruction(mnemonic: str, operands: str, arch: str, info: ArchInfo | None = None) -> bool:
    info = info or get_raw_arch_info(arch)
    if info is None:
        return False
    mnem = str(mnemonic or "").lower()
    return info.adapter.is_return_instruction(mnem, operands)


def _find_non_x86_gadgets(
    data: bytes,
    arch: str,
    max_insns: int,
    *,
    base_addr: int = 0,
    arch_info: ArchInfo | None = None,
) -> list[dict[str, Any]]:
    try:
        import capstone

        info = arch_info or get_raw_arch_info(arch)
        if info is None or info.capstone_tuple is None:
            return []
        md = capstone.Cs(*info.capstone_tuple)
        md.skipdata = True
        insns = list(md.disasm(data, base_addr))
    except Exception:
        return []

    gadgets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, insn in enumerate(insns):
        if not _is_return_instruction(insn.mnemonic, insn.op_str, arch, info):
            continue
        start_idx = max(0, idx - max_insns + 1)
        window = insns[start_idx : idx + 1]
        if not window or len(window) > max_insns:
            continue
        rendered = [f"{i.mnemonic} {i.op_str}".strip() for i in window]
        key = "|".join(rendered)
        if key in seen:
            continue
        seen.add(key)
        support = get_feature_support(info.adapter, "rop_gadgets")
        gadgets.append(
            {
                "addr": hex(window[0].address),
                "instructions": rendered,
                "type": _classify_gadget(rendered),
                "regs_modified": _modified_registers(rendered),
                "support_level": support.level,
                "support_note": support.note,
            }
        )
    return gadgets


def _section_is_executable(section: Any, binary: Any) -> bool:
    if not lief or binary is None:
        return True
    try:
        if isinstance(binary, lief.ELF.Binary):
            return lief.ELF.Section.FLAGS.EXECINSTR in getattr(section, "flags_list", [])
        if isinstance(binary, lief.PE.Binary):
            return lief.PE.Section.CHARACTERISTICS.CNT_CODE in getattr(section, "characteristics_list", [])
        if isinstance(binary, lief.MachO.Binary):
            segment_name = str(getattr(section, "segment_name", "") or "").strip("\x00")
            return segment_name == "__TEXT"
    except Exception:
        pass
    flags_text = " ".join(str(flag).upper() for flag in getattr(section, "flags_list", []) or [])
    characteristics_text = " ".join(str(flag).upper() for flag in getattr(section, "characteristics_list", []) or [])
    return "EXEC" in flags_text or "CNT_CODE" in characteristics_text


def _section_virtual_address(section: Any, binary: Any) -> int:
    va = int(getattr(section, "virtual_address", 0) or 0)
    try:
        if lief and isinstance(binary, lief.PE.Binary):
            imagebase = int(getattr(getattr(binary, "optional_header", None), "imagebase", 0) or 0)
            if imagebase and va < imagebase:
                return imagebase + va
    except Exception:
        pass
    return va


def _iter_executable_regions(binary_path: str) -> list[tuple[int, bytes]]:
    if not lief:
        return []
    try:
        binary = lief.parse(binary_path)
    except Exception:
        return []
    if binary is None:
        return []
    regions: list[tuple[int, bytes]] = []
    for section in getattr(binary, "sections", []) or []:
        if not _section_is_executable(section, binary):
            continue
        content = bytes(getattr(section, "content", b"") or b"")
        if not content:
            continue
        regions.append((_section_virtual_address(section, binary), content))
    return regions


def _detect_arch_for_file(binary_path: str, requested_arch: str | None) -> ArchInfo | None:
    requested = str(requested_arch or "").strip()
    if requested and requested.lower() not in {"auto", "detect"}:
        return get_raw_arch_info(requested)
    return detect_binary_arch_from_path(binary_path)


def find_gadgets(
    binary_path: str, arch: str = "auto", max_insns: int = 5
) -> list[dict[str, Any]]:
    try:
        data = Path(binary_path).read_bytes()
    except Exception as e:
        _log.warning("Cannot read binary %s: %s", binary_path, e)
        return []

    info = _detect_arch_for_file(binary_path, arch)
    if info is None:
        info = get_raw_arch_info("x86_64")
    arch_name = info.raw_name if info is not None else (arch or "x86_64")

    if info is not None and info.family != "x86":
        regions = _iter_executable_regions(binary_path)
        if not regions:
            regions = [(0, data)]
        gadgets: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for base_addr, region in regions:
            for gadget in _find_non_x86_gadgets(
                region,
                arch_name,
                max_insns,
                base_addr=base_addr,
                arch_info=info,
            ):
                key = (str(gadget.get("addr")), "|".join(gadget.get("instructions", [])))
                if key in seen:
                    continue
                seen.add(key)
                gadgets.append(gadget)
        return gadgets

    support = get_feature_support(info.adapter if info else "x86_64", "rop_gadgets")
    regions = _iter_executable_regions(binary_path)
    if not regions:
        regions = [(0, data)]
    gadgets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for base_addr, region in regions:
        for gadget in _find_x86_gadgets(region, arch_name, max_insns, support, base_addr=base_addr):
            key = (str(gadget.get("addr")), "|".join(gadget.get("instructions", [])))
            if key in seen:
                continue
            seen.add(key)
            gadgets.append(gadget)

    return gadgets


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--arch", default="auto")
    parser.add_argument("--max-insns", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(find_gadgets(args.binary, args.arch, args.max_insns), indent=2))
