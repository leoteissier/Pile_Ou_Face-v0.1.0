"""Binary Diff — compare deux binaires au niveau des fonctions.

Algorithme hybride :
  Phase 1 — symbol-name matching (si noms disponibles)
  Phase 2 — basic-block hash Jaccard fallback (binaires strippés)

Output JSON : {ok, functions, stats, meta}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import warnings
from difflib import SequenceMatcher
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backends.shared.exceptions import BinaryNotFoundError, BinaryParseError
from backends.static.arch import ArchInfo, detect_binary_arch

try:
    import capstone
except ImportError:
    capstone = None

try:
    import lief
except ImportError:
    lief = None


def _make_meta(module: str, **kwargs) -> dict:
    from datetime import datetime, timezone

    d = {"module": module, "timestamp": datetime.now(timezone.utc).isoformat()}
    d.update(kwargs)
    return d


def _get_arch_info(binary) -> ArchInfo | None:
    """Return centralized architecture information for a parsed LIEF binary."""
    if not capstone or not lief:
        return None
    info = detect_binary_arch(binary)
    if info is None or info.capstone_tuple is None:
        return None
    return info


def _get_arch_mode(binary) -> tuple[int, int] | None:
    """Return (capstone_arch, capstone_mode) or None if unsupported."""
    info = _get_arch_info(binary)
    return info.capstone_tuple if info else None


def _get_section_bytes(binary, addr: int) -> tuple[bytes, int] | None:
    """Return (bytes_slice_from_addr, addr) for the section containing addr."""
    if isinstance(binary, lief.PE.Binary):
        base = binary.optional_header.imagebase
        for sec in binary.sections:
            va = sec.virtual_address + base
            content = bytes(sec.content)
            if content and va <= addr < va + len(content):
                return content[addr - va :], addr
        return None

    if isinstance(binary, lief.ELF.Binary):
        sections = list(binary.sections)
    elif isinstance(binary, lief.MachO.Binary):
        sections = list(binary.sections)
    else:
        return None

    for sec in sections:
        va = sec.virtual_address
        content = bytes(sec.content)
        if content and va <= addr < va + len(content):
            return content[addr - va :], addr
    return None


def _normalize_insn(insn) -> str:
    """Normalize a capstone instruction: replace addresses/immediates with tokens."""
    op = re.sub(r"0x[0-9a-fA-F]+", "ADDR", insn.op_str)
    op = re.sub(r"\b\d+\b", "IMM", op)
    return f"{insn.mnemonic} {op}".strip()


_BRANCH_MNEMS = frozenset(
    {
        # x86 / x86-64
        "jmp",
        "call",
        "je",
        "jne",
        "jz",
        "jnz",
        "jl",
        "jle",
        "jg",
        "jge",
        "jb",
        "jbe",
        "ja",
        "jae",
        "js",
        "jns",
        "jp",
        "jnp",
        "jpe",
        "jpo",
        "jecxz",
        "jrcxz",
        "loop",
        "loope",
        "loopne",
        # ARM64 / AArch64
        "b",
        "bl",
        "br",
        "blr",
        "b.eq",
        "b.ne",
        "b.cs",
        "b.hs",
        "b.cc",
        "b.lo",
        "b.mi",
        "b.pl",
        "b.vs",
        "b.vc",
        "b.hi",
        "b.ls",
        "b.ge",
        "b.lt",
        "b.gt",
        "b.le",
        "b.al",
        "cbz",
        "cbnz",
        "tbz",
        "tbnz",
    }
)


def _is_block_terminator(insn: dict, arch_info: ArchInfo) -> bool:
    mnemonic = str(insn.get("mnem") or "").lower()
    operands = str(insn.get("op_str") or "")
    adapter = arch_info.adapter
    if adapter.is_return_instruction(mnemonic, operands):
        return True
    if adapter.is_call_mnemonic(mnemonic):
        return False
    if adapter.is_unconditional_jump_mnemonic(mnemonic):
        return True
    if adapter.is_conditional_branch_mnemonic(mnemonic):
        return True
    return mnemonic in _BRANCH_MNEMS or mnemonic in ("ret", "retq", "retn", "retl")


def _disasm_func(
    binary, cs, arch_info: ArchInfo, func_addr: int, max_insns: int = 256
) -> list[dict]:
    """Disassemble up to max_insns instructions from func_addr."""
    code_data = _get_section_bytes(binary, func_addr)
    if not code_data:
        return []
    code_bytes, base = code_data
    result = []
    for ins in cs.disasm(code_bytes, base):
        result.append(
            {
                "addr": hex(ins.address),
                "mnem": str(ins.mnemonic or "").lower(),
                "op_str": ins.op_str,
                "norm": _normalize_insn(ins),
                "asm": f"{ins.mnemonic} {ins.op_str}".strip(),
            }
        )
        if arch_info.adapter.is_return_instruction(ins.mnemonic, ins.op_str):
            break
        if len(result) >= max_insns:
            break
    return result


def _build_basic_blocks(
    insns: list[dict], arch_info: ArchInfo, key: str = "norm"
) -> list[tuple]:
    """Split instruction list into basic blocks (split on branches/ret)."""
    blocks = []
    current: list[str] = []
    for insn in insns:
        current.append(insn[key])
        if _is_block_terminator(insn, arch_info):
            if current:
                blocks.append(tuple(current))
                current = []
    if current:
        blocks.append(tuple(current))
    return blocks


def _block_hash(block: tuple) -> str:
    return hashlib.sha256("|".join(block).encode()).hexdigest()[:16]


def _jaccard(blocks_a: list[tuple], blocks_b: list[tuple]) -> float:
    """Jaccard similarity over block hash sets."""
    if not blocks_a and not blocks_b:
        return 1.0
    if not blocks_a or not blocks_b:
        return 0.0
    ha = {_block_hash(b) for b in blocks_a}
    hb = {_block_hash(b) for b in blocks_b}
    inter = len(ha & hb)
    union = len(ha | hb)
    return inter / union if union else 0.0


def _diff_instructions(insns_a: list[dict], insns_b: list[dict]) -> list[dict]:
    """LCS-based instruction diff. Returns list of {type, asm, addr_a, addr_b}."""
    asm_a = [i["asm"] for i in insns_a]
    asm_b = [i["asm"] for i in insns_b]
    sm = SequenceMatcher(None, asm_a, asm_b, autojunk=False)
    result = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                result.append(
                    {
                        "type": "equal",
                        "asm": insns_a[i1 + k]["asm"],
                        "addr_a": insns_a[i1 + k]["addr"],
                        "addr_b": insns_b[j1 + k]["addr"],
                    }
                )
        elif tag in ("replace", "delete"):
            for k in range(i2 - i1):
                result.append(
                    {
                        "type": "removed",
                        "asm": insns_a[i1 + k]["asm"],
                        "addr_a": insns_a[i1 + k]["addr"],
                        "addr_b": None,
                    }
                )
        if tag in ("replace", "insert"):
            for k in range(j2 - j1):
                result.append(
                    {
                        "type": "added",
                        "asm": insns_b[j1 + k]["asm"],
                        "addr_a": None,
                        "addr_b": insns_b[j1 + k]["addr"],
                    }
                )
    return result


def _sym_name(raw) -> str:
    """Convert a lief symbol name (str or bytes) to str."""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw or ""


def _build_func_map(binary, arch_info: ArchInfo) -> dict[str, dict]:
    """Return {name -> {name, addr, insns, blocks}} for all functions in binary."""
    func_map: dict[str, dict] = {}
    cs = capstone.Cs(*arch_info.capstone_tuple)  # type: ignore[union-attr,arg-type]
    if isinstance(binary, lief.ELF.Binary):  # type: ignore[union-attr]
        syms = [
            s
            for s in binary.symbols
            if s.type == lief.ELF.Symbol.TYPE.FUNC and s.value != 0
        ]  # type: ignore[union-attr]
    elif isinstance(binary, lief.MachO.Binary):  # type: ignore[union-attr]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            syms = [
                s
                for s in binary.symbols
                if s.value != 0 and s.type == lief.MachO.Symbol.TYPE.SECTION
            ]  # type: ignore[union-attr]
    elif isinstance(binary, lief.PE.Binary):  # type: ignore[union-attr]
        syms = [
            s
            for s in binary.symbols
            if s.value != 0 and s.storage_class == lief.PE.Symbol.STORAGE_CLASS.FUNCTION
        ]  # type: ignore[union-attr]
    else:
        syms = []
    for sym in syms:
        try:
            addr = sym.value
            name = _sym_name(sym.name) or f"sub_{addr:x}"
            insns = _disasm_func(binary, cs, arch_info, addr)
            func_map[name] = {
                "name": name,
                "addr": hex(addr),
                "insns": insns,
                "blocks": _build_basic_blocks(insns, arch_info, "norm"),
                "blocks_exact": _build_basic_blocks(insns, arch_info, "asm"),
            }
        except Exception:
            pass
    return func_map


def _match_functions(map_a: dict, map_b: dict, threshold: float) -> list[dict]:
    """Match functions and return diff list."""
    results = []
    matched_b: set[str] = set()

    for name, fa in map_a.items():
        if name in map_b:
            # Phase 1: exact name match
            fb = map_b[name]
            matched_b.add(name)
            # Use exact (non-normalized) blocks for similarity
            sim = _jaccard(fa["blocks_exact"], fb["blocks_exact"])
            status = "identical" if sim == 1.0 else "modified"
            diff = (
                []
                if status == "identical"
                else _diff_instructions(fa["insns"], fb["insns"])
            )
            results.append(
                {
                    "name": name,
                    "addr_a": fa["addr"],
                    "addr_b": fb["addr"],
                    "status": status,
                    "similarity": round(sim, 4),
                    "diff": diff,
                }
            )
        else:
            # Phase 2: best block-hash match among unmatched B funcs
            # Use normalized blocks for fuzzy matching across different names
            best_name, best_fb, best_sim = None, None, 0.0
            if fa["blocks"]:
                for b_name, fb in map_b.items():
                    if b_name in matched_b or not fb["blocks"]:
                        continue
                    sim = _jaccard(fa["blocks"], fb["blocks"])
                    if sim > best_sim:
                        best_sim, best_name, best_fb = sim, b_name, fb

            if best_fb and best_name and best_sim >= threshold:
                matched_b.add(best_name)
                # Re-compute similarity with exact blocks for accurate score
                exact_sim = _jaccard(fa["blocks_exact"], best_fb["blocks_exact"])
                status = "identical" if exact_sim == 1.0 else "modified"
                diff = (
                    []
                    if status == "identical"
                    else _diff_instructions(fa["insns"], best_fb["insns"])
                )
                results.append(
                    {
                        "name": name,
                        "addr_a": fa["addr"],
                        "addr_b": best_fb["addr"],
                        "status": status,
                        "similarity": round(exact_sim, 4),
                        "diff": diff,
                    }
                )
            else:
                results.append(
                    {
                        "name": name,
                        "addr_a": fa["addr"],
                        "addr_b": None,
                        "status": "removed",
                        "similarity": 0.0,
                        "diff": [],
                    }
                )

    # Added: funcs only in B
    for b_name, fb in map_b.items():
        if b_name not in matched_b:
            results.append(
                {
                    "name": b_name,
                    "addr_a": None,
                    "addr_b": fb["addr"],
                    "status": "added",
                    "similarity": 0.0,
                    "diff": [],
                }
            )
    return results


def diff_binaries(
    binary_path_a: str, binary_path_b: str, threshold: float = 0.60
) -> dict:
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f"threshold must be in [0.0, 1.0], got {threshold}")
    for p in (binary_path_a, binary_path_b):
        if not Path(p).exists():
            raise BinaryNotFoundError(f"Binary not found: {p}")

    if not lief or not capstone:
        return {
            "ok": False,
            "error": "lief and capstone are required",
            "functions": [],
            "stats": {},
            "meta": _make_meta(
                "bindiff",
                threshold=threshold,
                binary_a=binary_path_a,
                binary_b=binary_path_b,
            ),
        }

    try:
        ba = lief.parse(binary_path_a)
        bb = lief.parse(binary_path_b)
    except Exception as exc:
        raise BinaryParseError("Failed to parse binaries") from exc

    if ba is None or bb is None:
        raise BinaryParseError("lief could not parse one or both binaries")

    arch_a = _get_arch_info(ba)
    arch_b = _get_arch_info(bb)
    if not arch_a or not arch_b:
        return {
            "ok": False,
            "error": "Unsupported architecture or missing Capstone profile",
            "functions": [],
            "stats": {},
            "meta": _make_meta(
                "bindiff",
                threshold=threshold,
                binary_a=binary_path_a,
                binary_b=binary_path_b,
            ),
        }

    map_a = _build_func_map(ba, arch_a)
    map_b = _build_func_map(bb, arch_b)
    functions = _match_functions(map_a, map_b, threshold)

    stats: dict[str, int] = {"identical": 0, "modified": 0, "added": 0, "removed": 0}
    for f in functions:
        stats[f["status"]] += 1

    return {
        "ok": True,
        "functions": functions,
        "stats": stats,
        "meta": _make_meta(
            "bindiff",
            threshold=threshold,
            binary_a=binary_path_a,
            binary_b=binary_path_b,
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Binary diff — compare two binaries at function level"
    )
    parser.add_argument("--binary-a", required=True, dest="binary_a")
    parser.add_argument("--binary-b", required=True, dest="binary_b")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.60,
        help="Jaccard similarity threshold 0-1 (default 0.60)",
    )
    args = parser.parse_args()
    meta = _make_meta(
        "bindiff",
        threshold=args.threshold,
        binary_a=args.binary_a,
        binary_b=args.binary_b,
    )

    try:
        result = diff_binaries(args.binary_a, args.binary_b, args.threshold)
    except (BinaryNotFoundError, BinaryParseError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "functions": [],
                    "stats": {},
                    "meta": meta,
                }
            )
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "functions": [],
                    "stats": {},
                    "meta": meta,
                }
            )
        )
        return 1

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
