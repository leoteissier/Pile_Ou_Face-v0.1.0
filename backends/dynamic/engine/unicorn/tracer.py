# -----------------------------------------------------------------------------
# Core Unicorn tracing engine for raw binaries and ELF executables.
# Maps memory, initializes stack/argv/auxv, installs hooks, and collects snapshots.
# Supports PIE/interpreter loading, start symbol overrides, and addr2line enrichment.
# -----------------------------------------------------------------------------

"""@file tracer.py
@brief Coeur de trace Unicorn (raw + ELF).

@details Mappe la memoire, installe hooks et construit des snapshots.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional

try:
    from unicorn import Uc, UcError
    from unicorn import (
        UC_ARCH_X86,
        UC_MODE_32,
        UC_MODE_64,
        UC_HOOK_CODE,
        UC_HOOK_INSN,
        UC_HOOK_INTR,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_PROT_ALL,
    )
    from unicorn.x86_const import (
        UC_X86_INS_SYSCALL,
        UC_X86_REG_EAX,
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDI,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_RSI,
        UC_X86_REG_RDX,
    )
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Unicorn is required. Install with: pip install unicorn") from exc

from .config import TraceConfig
from .elf import parse_elf_header, parse_program_headers, read_c_string
from .hooks import SnapshotCollector
from .io import is_elf, load_code
from .regs import get_pc_sp, get_reg_order, get_rbp
from .resolve import addr2line_map, resolve_symbol_addr
from .stack import align_up, build_initial_stack, init_stack, inject_stack_payload
from .syscalls import ReadSyscallEmulator


def _in_capture_ranges(addr: int, capture_ranges: Optional[List[tuple]]) -> bool:
    if not capture_ranges:
        return True
    return any(start <= addr < end for start, end in capture_ranges)


def _read_word(uc, addr: int, word_size: int) -> Optional[int]:
    try:
        raw = bytes(uc.mem_read(addr, word_size))
    except UcError:
        return None
    return int.from_bytes(raw, "little", signed=False)


def _safe_read_bytes(uc, addr: int, size: int) -> bytes:
    if size <= 0:
        return b""
    try:
        return bytes(uc.mem_read(addr, size))
    except UcError:
        return b""


def _infer_call_target_from_return(uc, ret_addr: int, arch_bits: int) -> Optional[int]:
    # call rel32: E8 xx xx xx xx
    try:
        insn = bytes(uc.mem_read(ret_addr - 5, 5))
    except UcError:
        return None
    if len(insn) != 5 or insn[0] != 0xE8:
        return None
    rel = int.from_bytes(insn[1:], "little", signed=True)
    mask = 0xFFFFFFFFFFFFFFFF if arch_bits == 64 else 0xFFFFFFFF
    return (ret_addr + rel) & mask


def _copy_c_string(uc, src: int, dst: int, max_len: int = 0x20000) -> Optional[int]:
    if src == 0 or dst == 0:
        return None
    copied = 0
    try:
        while copied < max_len:
            byte = bytes(uc.mem_read(src + copied, 1))
            uc.mem_write(dst + copied, byte)
            copied += 1
            if byte == b"\x00":
                break
    except UcError:
        return None
    return copied


def _copy_n_bytes(uc, src: int, dst: int, n: int) -> Optional[int]:
    if src == 0 or dst == 0 or n < 0:
        return None
    if n == 0:
        return 0
    try:
        blob = bytes(uc.mem_read(src, n))
        uc.mem_write(dst, blob)
    except UcError:
        return None
    return n


def _memset_bytes(uc, dst: int, value: int, n: int) -> Optional[int]:
    if dst == 0 or n < 0:
        return None
    if n == 0:
        return 0
    try:
        uc.mem_write(dst, bytes([value & 0xFF]) * n)
    except UcError:
        return None
    return n


def _strlen_at(uc, src: int, max_len: int = 0x20000) -> Optional[int]:
    if src == 0:
        return None
    length = 0
    try:
        while length < max_len:
            byte = bytes(uc.mem_read(src + length, 1))
            if byte == b"\x00":
                return length
            length += 1
    except UcError:
        return None
    return None


def _strcmp_at(
    uc, lhs: int, rhs: int, max_len: int = 0x20000, limit: Optional[int] = None
) -> Optional[int]:
    if lhs == 0 or rhs == 0:
        return None
    i = 0
    try:
        while i < max_len:
            if limit is not None and i >= limit:
                return 0
            a = bytes(uc.mem_read(lhs + i, 1))[0]
            b = bytes(uc.mem_read(rhs + i, 1))[0]
            if a != b:
                return int(a) - int(b)
            if a == 0:
                return 0
            i += 1
    except UcError:
        return None
    return None


def _consume_stdin_bytes(state: dict, n: int) -> bytes:
    if n <= 0:
        return b""
    data = state.get("stdin_data", b"")
    pos = int(state.get("stdin_pos", 0))
    if pos >= len(data):
        return b""
    chunk = data[pos : pos + n]
    state["stdin_pos"] = pos + len(chunk)
    return chunk


def _consume_stdin_line(state: dict, max_len: int) -> bytes:
    if max_len <= 0:
        return b""
    data = state.get("stdin_data", b"")
    pos = int(state.get("stdin_pos", 0))
    if pos >= len(data):
        return b""
    end = min(len(data), pos + max_len)
    chunk = data[pos:end]
    nl = chunk.find(b"\n")
    if nl >= 0:
        chunk = chunk[: nl + 1]
    state["stdin_pos"] = pos + len(chunk)
    return chunk


def _bytes_to_hex(data: bytes | bytearray | list[int]) -> str:
    return " ".join(f"{int(byte) & 0xFF:02x}" for byte in bytes(data))


def _begin_external_event(
    state: dict,
    instruction_addr: int,
    symbol_name: Optional[str],
    call_target: Optional[int],
) -> None:
    state["current_external_event"] = {
        "instruction_addr": int(instruction_addr),
        "external_symbol": symbol_name,
        "call_target": hex(call_target) if call_target is not None else None,
        "external_simulated": False,
        "reads": [],
        "writes": [],
    }


def _record_external_access(
    state: dict,
    kind: str,
    addr: Optional[int],
    size: Optional[int],
    data: bytes | None = None,
) -> None:
    event = state.get("current_external_event")
    if not isinstance(event, dict):
        return
    if addr is None or size is None or size <= 0:
        return
    entry = {
        "addr": hex(int(addr)),
        "size": int(size),
        "bytes": _bytes_to_hex(data or b""),
        "source": "external",
    }
    bucket = event.setdefault(kind, [])
    if isinstance(bucket, list):
        bucket.append(entry)


def _commit_external_event(state: dict, simulated: bool) -> None:
    event = state.pop("current_external_event", None)
    if not isinstance(event, dict):
        return
    event["external_simulated"] = bool(simulated)
    events_by_addr = state.setdefault("events_by_addr", {})
    if not isinstance(events_by_addr, dict):
        return
    instruction_addr = event.get("instruction_addr")
    if not isinstance(instruction_addr, int):
        return
    events_by_addr.setdefault(instruction_addr, []).append(event)


def _symbol_key(symbol_name: Optional[str]) -> Optional[str]:
    if not symbol_name:
        return None
    plain = symbol_name.split("@", 1)[0]
    if plain.startswith("__isoc99_"):
        plain = plain[len("__isoc99_") :]
    if plain.startswith("__GI_"):
        plain = plain[len("__GI_") :]
    return plain


def _read_call_arg(
    uc,
    arch_bits: int,
    index: int,
    stack_base: int,
    word_size: int,
) -> Optional[int]:
    if arch_bits == 64:
        reg_order = [
            UC_X86_REG_RDI,
            UC_X86_REG_RSI,
            UC_X86_REG_RDX,
            UC_X86_REG_RCX,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
        ]
        if index < len(reg_order):
            try:
                return int(uc.reg_read(reg_order[index]))
            except UcError:
                return None
        # Stack args beyond the first 6 are uncommon for our simulated libc calls.
        return None
    return _read_word(uc, stack_base + (index * word_size), word_size)


def _simulate_symbol_with_args(
    uc,
    arch_bits: int,
    symbol_name: Optional[str],
    stack_base: int,
    word_size: int,
    state: dict,
) -> Optional[int]:
    key = _symbol_key(symbol_name)
    if not key:
        return None

    def arg(i: int) -> Optional[int]:
        return _read_call_arg(uc, arch_bits, i, stack_base, word_size)

    def mark() -> None:
        per_symbol = state.setdefault("simulated_by_symbol", {})
        per_symbol[key] = int(per_symbol.get(key, 0)) + 1

    if key in {"strcpy", "__strcpy_chk"}:
        dst, src = arg(0), arg(1)
        if dst is None or src is None:
            return None
        copied = _copy_c_string(uc, src, dst)
        if copied is None:
            return None
        _record_external_access(state, "reads", src, copied)
        _record_external_access(
            state,
            "writes",
            dst,
            copied,
            _safe_read_bytes(uc, dst, copied),
        )
        mark()
        return dst

    if key in {"stpcpy"}:
        dst, src = arg(0), arg(1)
        if dst is None or src is None:
            return None
        copied = _copy_c_string(uc, src, dst)
        if copied is None:
            return None
        _record_external_access(state, "reads", src, copied)
        _record_external_access(
            state,
            "writes",
            dst,
            copied,
            _safe_read_bytes(uc, dst, copied),
        )
        mark()
        return dst + max(copied - 1, 0)

    if key in {"strncpy", "__strncpy_chk"}:
        dst, src, n = arg(0), arg(1), arg(2)
        if dst is None or src is None or n is None:
            return None
        if n < 0:
            return None
        if n == 0:
            mark()
            return dst
        copied = _copy_c_string(uc, src, dst, max_len=n if n > 0 else 1)
        if copied is None:
            return None
        # strncpy pads with NUL bytes when src length < n.
        if copied < n:
            _memset_bytes(uc, dst + copied, 0, n - copied)
        _record_external_access(state, "reads", src, copied)
        _record_external_access(
            state,
            "writes",
            dst,
            n,
            _safe_read_bytes(uc, dst, n),
        )
        mark()
        return dst

    if key in {"memcpy", "__memcpy_chk", "memmove"}:
        dst, src, n = arg(0), arg(1), arg(2)
        if dst is None or src is None or n is None:
            return None
        copied = _copy_n_bytes(uc, src, dst, n)
        if copied is None:
            return None
        _record_external_access(state, "reads", src, copied)
        _record_external_access(
            state,
            "writes",
            dst,
            copied,
            _safe_read_bytes(uc, dst, copied),
        )
        mark()
        return dst

    if key in {"memset", "__memset_chk", "bzero"}:
        if key == "bzero":
            dst, n = arg(0), arg(1)
            value = 0
        else:
            dst, value, n = arg(0), arg(1), arg(2)
        if dst is None or n is None:
            return None
        if value is None:
            value = 0
        wrote = _memset_bytes(uc, dst, value, n)
        if wrote is None:
            return None
        _record_external_access(
            state,
            "writes",
            dst,
            wrote,
            _safe_read_bytes(uc, dst, wrote),
        )
        mark()
        return dst

    if key in {"strlen"}:
        src = arg(0)
        if src is None:
            return None
        n = _strlen_at(uc, src)
        if n is None:
            return None
        _record_external_access(state, "reads", src, n + 1)
        mark()
        return n

    if key in {"strcmp"}:
        lhs, rhs = arg(0), arg(1)
        if lhs is None or rhs is None:
            return None
        cmp_val = _strcmp_at(uc, lhs, rhs)
        if cmp_val is None:
            return None
        mark()
        return cmp_val

    if key in {"strncmp"}:
        lhs, rhs, n = arg(0), arg(1), arg(2)
        if lhs is None or rhs is None or n is None:
            return None
        cmp_val = _strcmp_at(uc, lhs, rhs, limit=n)
        if cmp_val is None:
            return None
        mark()
        return cmp_val

    if key in {"gets"}:
        dst = arg(0)
        if dst is None:
            return None
        chunk = _consume_stdin_line(state, 0x10000)
        if chunk.endswith(b"\n"):
            chunk = chunk[:-1]
        try:
            uc.mem_write(dst, chunk + b"\x00")
        except UcError:
            return None
        _record_external_access(
            state,
            "writes",
            dst,
            len(chunk) + 1,
            chunk + b"\x00",
        )
        mark()
        return dst

    if key in {"fgets"}:
        dst, n = arg(0), arg(1)
        if dst is None or n is None or n <= 0:
            return None
        chunk = _consume_stdin_line(state, max(0, n - 1))
        try:
            uc.mem_write(dst, chunk + b"\x00")
        except UcError:
            return None
        _record_external_access(
            state,
            "writes",
            dst,
            len(chunk) + 1,
            chunk + b"\x00",
        )
        mark()
        return dst if chunk else 0

    if key in {"read"}:
        fd, dst, n = arg(0), arg(1), arg(2)
        if fd is None or dst is None or n is None:
            return None
        if fd != 0:
            mark()
            return 0
        chunk = _consume_stdin_bytes(state, n)
        try:
            if chunk:
                uc.mem_write(dst, chunk)
        except UcError:
            return None
        if chunk:
            _record_external_access(state, "writes", dst, len(chunk), chunk)
        mark()
        return len(chunk)

    if key in {"puts", "printf", "fprintf", "__printf_chk", "perror"}:
        # Ignore output side effects, but keep control flow moving.
        mark()
        return 1

    if key in {"exit", "_exit", "abort", "__stack_chk_fail"}:
        try:
            uc.emu_stop()
        except UcError:
            pass
        mark()
        return 0

    return None


def _simulate_external_call(
    uc,
    arch_bits: int,
    symbol_name: Optional[str],
    ret_slot_addr: int,
    word_size: int,
    state: dict,
) -> Optional[int]:
    # Post-call context (fallback path): args are after return address on 32-bit.
    stack_base = ret_slot_addr + (word_size if arch_bits == 32 else 0)
    return _simulate_symbol_with_args(
        uc, arch_bits, symbol_name, stack_base, word_size, state
    )


def _simulate_external_call_precall(
    uc,
    arch_bits: int,
    symbol_name: Optional[str],
    sp: int,
    word_size: int,
    state: dict,
) -> Optional[int]:
    # Pre-call context: stack args start at current SP (32-bit).
    return _simulate_symbol_with_args(uc, arch_bits, symbol_name, sp, word_size, state)


def _find_return_slot(
    uc, sp: int, word_size: int, capture_ranges: Optional[List[tuple]]
) -> Optional[tuple]:
    max_scan_words = 16
    for idx in range(max_scan_words):
        slot_addr = sp + (idx * word_size)
        ret_addr = _read_word(uc, slot_addr, word_size)
        if ret_addr is None or ret_addr == 0:
            continue
        if not _in_capture_ranges(ret_addr, capture_ranges):
            continue
        try:
            uc.mem_read(ret_addr, 1)
        except UcError:
            continue
        return ret_addr, slot_addr
    return None


def _load_plt_symbols(binary_path: Optional[str], base_adjust: int) -> Dict[int, str]:
    if not binary_path or not shutil.which("objdump"):
        return {}
    try:
        result = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return {}
    if result.returncode != 0:
        return {}

    plt_symbols: Dict[int, str] = {}
    pattern = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)@plt(?:\.sec)?>:")
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        try:
            addr = int(match.group(1), 16) + base_adjust
        except ValueError:
            continue
        plt_symbols[addr] = match.group(2)
    return plt_symbols


def _install_external_fetch_skip_hook(
    uc,
    config: TraceConfig,
    arch_bits: int,
    plt_symbols: Optional[Dict[int, str]] = None,
    shared_state: Optional[dict] = None,
) -> dict:
    """Skip external/libc calls (pre-call for PLT, fallback on unmapped fetch)."""
    pc_reg, sp_reg = get_pc_sp(arch_bits)
    word_size = 8 if arch_bits == 64 else 4
    ret_reg = UC_X86_REG_RAX if arch_bits == 64 else UC_X86_REG_EAX
    plt_map = dict(plt_symbols or {})
    mask = 0xFFFFFFFFFFFFFFFF if arch_bits == 64 else 0xFFFFFFFF
    state = shared_state if isinstance(shared_state, dict) else {}
    state.update(
        {
            "capture_ranges": (
                list(config.capture_ranges) if config.capture_ranges else None
            ),
            "word_size": word_size,
            "sp_reg": sp_reg,
            "pc_reg": pc_reg,
            "ret_reg": ret_reg,
            "arch_bits": arch_bits,
            "plt_symbols": plt_map,
            "skipped_external": int(state.get("skipped_external", 0)),
            "simulated_strcpy": int(state.get("simulated_strcpy", 0)),
            "simulated_by_symbol": dict(state.get("simulated_by_symbol", {})),
            "stdin_data": bytes(config.stdin_data),
            "stdin_pos": int(state.get("stdin_pos", 0)),
            "events_by_addr": state.get("events_by_addr", {}),
        }
    )

    def _hook_code_pre_call_skip(uc_engine, addr, size, user_data):
        # Proactive skip for direct CALL rel32 into PLT.
        if size < 5:
            return
        try:
            insn = bytes(uc_engine.mem_read(addr, size))
        except UcError:
            return
        if len(insn) < 5 or insn[0] != 0xE8:
            return

        rel = int.from_bytes(insn[1:5], "little", signed=True)
        target = (addr + size + rel) & mask
        symbol_name = user_data["plt_symbols"].get(target)
        if not symbol_name:
            return

        try:
            sp = uc_engine.reg_read(user_data["sp_reg"])
            _begin_external_event(user_data, addr, symbol_name, target)
            ret_value = 0
            simulated = _simulate_external_call_precall(
                uc_engine,
                user_data["arch_bits"],
                symbol_name,
                sp,
                user_data["word_size"],
                user_data,
            )
            if simulated is not None:
                ret_value = simulated
                if _symbol_key(symbol_name) in {"strcpy", "__strcpy_chk"}:
                    user_data["simulated_strcpy"] += 1

            next_pc = (addr + size) & mask
            uc_engine.reg_write(user_data["ret_reg"], ret_value)
            uc_engine.reg_write(user_data["pc_reg"], next_pc)
            user_data["skipped_external"] += 1
            _commit_external_event(user_data, True)
        except UcError:
            user_data.pop("current_external_event", None)
            return

    def _hook_mem_fetch_unmapped(
        uc_engine, _access, _address, _size, _value, user_data
    ):
        try:
            sp = uc_engine.reg_read(user_data["sp_reg"])
        except UcError:
            return False

        ret_slot = _find_return_slot(
            uc_engine,
            sp,
            user_data["word_size"],
            user_data["capture_ranges"],
        )
        if ret_slot is None:
            return False
        ret_addr, ret_slot_addr = ret_slot

        try:
            ret_value = 0
            call_target = _infer_call_target_from_return(
                uc_engine,
                ret_addr,
                user_data["arch_bits"],
            )
            symbol_name = (
                user_data["plt_symbols"].get(call_target)
                if call_target is not None
                else None
            )
            call_addr = ret_addr - 5 if ret_addr >= 5 else ret_addr
            _begin_external_event(user_data, call_addr, symbol_name, call_target)
            simulated = _simulate_external_call(
                uc_engine,
                user_data["arch_bits"],
                symbol_name,
                ret_slot_addr,
                user_data["word_size"],
                user_data,
            )
            if simulated is not None:
                ret_value = simulated
                if _symbol_key(symbol_name) in {"strcpy", "__strcpy_chk"}:
                    user_data["simulated_strcpy"] += 1

            next_sp = ret_slot_addr + user_data["word_size"]
            uc_engine.reg_write(user_data["sp_reg"], next_sp)
            uc_engine.reg_write(user_data["pc_reg"], ret_addr)
            uc_engine.reg_write(user_data["ret_reg"], ret_value)
        except UcError:
            user_data.pop("current_external_event", None)
            return False

        user_data["skipped_external"] += 1
        _commit_external_event(user_data, True)
        return True

    uc.hook_add(UC_HOOK_CODE, _hook_code_pre_call_skip, state)
    uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, _hook_mem_fetch_unmapped, state)
    return state


def _is_main_symbol(symbol: Optional[str]) -> bool:
    if not symbol:
        return False
    s = symbol.strip()
    return s in {"main", "_main"}


def _prepare_main_entry_context(
    uc,
    arch_bits: int,
    sp_reg: int,
    symbol: Optional[str],
    argc: int,
    argv_ptr: int,
    envp_ptr: int,
) -> None:
    """When tracing starts at main, emulate a proper C calling context."""
    if not _is_main_symbol(symbol):
        return

    word_size = 8 if arch_bits == 64 else 4
    sp = uc.reg_read(sp_reg)

    if arch_bits == 64:
        # System V ABI: argc/rdi, argv/rsi, envp/rdx, return address on stack.
        new_sp = sp - word_size
        uc.mem_write(new_sp, (0).to_bytes(word_size, "little", signed=False))
        uc.reg_write(sp_reg, new_sp)
        uc.reg_write(UC_X86_REG_RDI, argc)
        uc.reg_write(UC_X86_REG_RSI, argv_ptr)
        uc.reg_write(UC_X86_REG_RDX, envp_ptr)
        return

    # i386 cdecl: [esp]=ret, [esp+4]=argc, [esp+8]=argv, [esp+12]=envp
    new_sp = sp - (word_size * 4)
    uc.mem_write(
        new_sp + 0 * word_size, (0).to_bytes(word_size, "little", signed=False)
    )
    uc.mem_write(
        new_sp + 1 * word_size, int(argc).to_bytes(word_size, "little", signed=False)
    )
    uc.mem_write(
        new_sp + 2 * word_size,
        int(argv_ptr).to_bytes(word_size, "little", signed=False),
    )
    uc.mem_write(
        new_sp + 3 * word_size,
        int(envp_ptr).to_bytes(word_size, "little", signed=False),
    )
    uc.reg_write(sp_reg, new_sp)


# --- Raw binary tracing -----------------------------------------------------
# Trace un blob brut: mappe le code, initialise la pile, installe les hooks,
# exécute Unicorn, puis retourne snapshots + meta.


def trace_raw(
    code_bytes: bytes, config: TraceConfig, binary_path: Optional[str] = None
) -> Dict[str, object]:
    """@brief Trace un blob brut (raw) ou Mach-O.
    @param code_bytes Code machine a emuler.
    @param config Configuration de trace.
    @param binary_path Chemin du binaire (optionnel, pour résolution de symboles).
    @return Dictionnaire {snapshots, meta}.
    """
    if config.arch_bits == 32 and config.stack_base > 0xFFFFFFFF:
        # Ajuste la pile 32-bit si l'adresse dépasse l'espace adressable.
        config = TraceConfig(
            base=config.base,
            stack_base=0xBFF00000,
            stack_size=config.stack_size,
            max_steps=config.max_steps,
            stack_entries=config.stack_entries,
            arch_bits=config.arch_bits,
            interp_base=config.interp_base,
            start_interp=config.start_interp,
            stdin_data=config.stdin_data,
            buffer_offset=config.buffer_offset,
            buffer_size=config.buffer_size,
            start_symbol=config.start_symbol,
            argv1=config.argv1,
            memory_patches=config.memory_patches,
            stack_payload=config.stack_payload,
        )
    # Sélectionne le mode CPU Unicorn selon l'arch.
    mode = UC_MODE_64 if config.arch_bits == 64 else UC_MODE_32
    uc = Uc(UC_ARCH_X86, mode)

    # Détecte si c'est un Mach-O et détermine l'adresse de base
    is_macho = len(code_bytes) >= 4 and code_bytes[:4] in (
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xfe\xed\xfa\xce",
    )
    if is_macho:
        # Mach-O 64-bit sur macOS charge généralement à 0x100000000
        load_base = 0x100000000
    else:
        load_base = config.base

    # Plage du binaire pour ne capturer que le code utilisateur (pas libc/loader).
    if config.capture_ranges is not None:
        code_end = load_base + len(code_bytes)
        config = TraceConfig(
            base=config.base,
            stack_base=config.stack_base,
            stack_size=config.stack_size,
            max_steps=config.max_steps,
            stack_entries=config.stack_entries,
            arch_bits=config.arch_bits,
            interp_base=config.interp_base,
            start_interp=config.start_interp,
            stdin_data=config.stdin_data,
            buffer_offset=config.buffer_offset,
            buffer_size=config.buffer_size,
            start_symbol=config.start_symbol,
            argv1=config.argv1,
            stop_symbol=config.stop_symbol,
            capture_start_addr=config.capture_start_addr,
            loader_max_steps=config.loader_max_steps,
            capture_ranges=[(load_base, code_end)],
            stop_addr=config.stop_addr,
            memory_patches=config.memory_patches,
            stack_payload=config.stack_payload,
        )

    # Mappe le code brut en mémoire.
    code_size = align_up(len(code_bytes), 0x1000)
    uc.mem_map(load_base, code_size, UC_PROT_ALL)
    uc.mem_write(load_base, code_bytes)

    # Initialise la pile + prépare hooks/snapshots.
    sp = init_stack(uc, config)
    inject_stack_payload(uc, sp, config)

    sp_reg = get_pc_sp(config.arch_bits)[1]
    rbp_reg = get_rbp(config.arch_bits)
    reg_order = get_reg_order(config.arch_bits)
    external_state: dict = {}
    collector = SnapshotCollector(
        config,
        reg_order,
        sp_reg,
        rbp_reg,
        get_pc_sp(config.arch_bits)[0],
        external_state=external_state,
    )
    syscalls = ReadSyscallEmulator(config)
    plt_symbols = _load_plt_symbols(binary_path, 0 if is_macho else load_base)
    uc.hook_add(UC_HOOK_CODE, collector.hook_code)
    uc.hook_add(UC_HOOK_MEM_READ, collector.hook_mem_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, collector.hook_mem_write)
    external_skip_state = _install_external_fetch_skip_hook(
        uc,
        config,
        config.arch_bits,
        plt_symbols,
        shared_state=external_state,
    )
    uc.hook_add(UC_HOOK_INTR, syscalls.hook_intr)
    uc.hook_add(UC_HOOK_INSN, syscalls.hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    # Détermine le point de départ (symbole ou base).
    start_addr = (
        load_base if not is_macho else config.base
    )  # fallback si pas de symbole
    if binary_path and config.start_symbol:
        # Pour Mach-O, base_adjust = 0 car les adresses sont absolues
        symbol_addr = resolve_symbol_addr(
            binary_path,
            config.start_symbol,
            0,  # Pas d'ajustement PIE pour Mach-O
        )
        if symbol_addr is not None:
            start_addr = symbol_addr
    if binary_path and config.stop_symbol:
        stop_addr = resolve_symbol_addr(binary_path, config.stop_symbol, 0)
        if stop_addr is not None:
            config.stop_addr = stop_addr

    # Lancer l'émulation jusqu'à la fin du blob (ou erreur).
    error: Optional[str] = None
    try:
        end_addr = load_base + len(code_bytes)
        uc.emu_start(start_addr, end_addr)
    except UcError as exc:
        error = str(exc)
    finally:
        collector.finalize_pending(uc)

    return {
        "snapshots": collector.snapshots,
        "meta": {
            "steps": collector.step,
            "error": error,
            "base": hex(load_base),
            "stack_base": hex(config.stack_base),
            "stack_size": config.stack_size,
            "arch_bits": config.arch_bits,
            "word_size": 8 if config.arch_bits == 64 else 4,
            "endian": "little",
            "buffer_offset": config.buffer_offset,
            "buffer_size": config.buffer_size,
            "stdin_len": len(config.stdin_data),
            "skipped_external_calls": external_skip_state["skipped_external"],
            "simulated_strcpy_calls": external_skip_state["simulated_strcpy"],
            "simulated_external_calls": external_skip_state.get(
                "simulated_by_symbol", {}
            ),
            "stop_addr": (
                hex(config.stop_addr) if config.stop_addr is not None else None
            ),
        },
    }


# --- ELF tracing -------------------------------------------------------------
# Trace un ELF: parse header, mappe segments, charge l'interpréteur (si besoin),
# construit argv/auxv, exécute Unicorn, puis enrichit via addr2line.


def trace_elf(
    code_bytes: bytes, config: TraceConfig, binary_path: Optional[str]
) -> Dict[str, object]:
    """@brief Trace un binaire ELF.
    @param code_bytes Bytes ELF.
    @param config Configuration de trace.
    @param binary_path Chemin du binaire (optionnel).
    @return Dictionnaire {snapshots, meta}.
    """
    header = parse_elf_header(code_bytes)
    if header["machine"] != 3 and header["machine"] != 62:
        raise ValueError("Only x86/x86_64 ELF supported")

    # Choix du mode CPU à partir du header.
    arch_bits = 64 if header["class"] == 64 else 32
    mode = UC_MODE_64 if arch_bits == 64 else UC_MODE_32
    uc = Uc(UC_ARCH_X86, mode)

    entry = header["entry"]
    is_pie = header["type"] == 3  # ET_DYN
    base = config.base if is_pie else 0

    phdrs = parse_program_headers(code_bytes, header)
    page_size = 0x1000
    interp_path = None
    phdr_vaddr = base + header["phoff"]

    # Mapper tous les PT_LOAD et mémoriser PT_INTERP si présent.
    for ph in phdrs:
        if ph["type"] == 3:  # PT_INTERP
            interp_path = read_c_string(code_bytes, ph["offset"])
        if ph["type"] != 1:  # PT_LOAD
            continue
        seg_start = base + ph["vaddr"]
        seg_end = seg_start + ph["memsz"]
        map_start = seg_start & ~(page_size - 1)
        map_end = align_up(seg_end, page_size)
        uc.mem_map(map_start, map_end - map_start, UC_PROT_ALL)
        if ph["filesz"] > 0:
            data = code_bytes[ph["offset"] : ph["offset"] + ph["filesz"]]
            uc.mem_write(seg_start, data)

    # Charger l'interpréteur ELF (ld-linux) si requis.
    interp_entry = None
    interp_base = None
    if interp_path:
        if not os.path.isabs(interp_path) and binary_path:
            candidate = os.path.join(os.path.dirname(binary_path), interp_path)
            if os.path.exists(candidate):
                interp_path = candidate
        if os.path.exists(interp_path):
            interp_blob = load_code(interp_path)
            interp_header = parse_elf_header(interp_blob)
            interp_phdrs = parse_program_headers(interp_blob, interp_header)
            interp_base = config.interp_base
            if interp_header["type"] != 3:
                interp_base = 0
            for ph in interp_phdrs:
                if ph["type"] != 1:
                    continue
                seg_start = interp_base + ph["vaddr"]
                seg_end = seg_start + ph["memsz"]
                map_start = seg_start & ~(page_size - 1)
                map_end = align_up(seg_end, page_size)
                uc.mem_map(map_start, map_end - map_start, UC_PROT_ALL)
                if ph["filesz"] > 0:
                    data = interp_blob[ph["offset"] : ph["offset"] + ph["filesz"]]
                    uc.mem_write(seg_start, data)
            interp_entry = interp_base + interp_header["entry"]

    # Corrige l'adresse de base 32-bit si besoin.
    effective_interp_base = config.interp_base
    if arch_bits == 32 and effective_interp_base > 0xFFFFFFFF:
        effective_interp_base = 0xF7000000

    # Plages du binaire principal uniquement (exclut ld-linux, libc) pour filtrer les snapshots.
    binary_ranges: Optional[List[tuple]] = None
    if config.capture_ranges is not None:
        binary_ranges = [
            (base + ph["vaddr"], base + ph["vaddr"] + ph["memsz"])
            for ph in phdrs
            if ph["type"] == 1  # PT_LOAD
        ]

    # Recalcule la config avec l'entry ELF et l'arch détectée.
    config = TraceConfig(
        base=base + entry,
        stack_base=config.stack_base,
        stack_size=config.stack_size,
        max_steps=config.max_steps,
        stack_entries=config.stack_entries,
        arch_bits=arch_bits,
        interp_base=effective_interp_base,
        start_interp=config.start_interp,
        stdin_data=config.stdin_data,
        buffer_offset=config.buffer_offset,
        buffer_size=config.buffer_size,
        start_symbol=config.start_symbol,
        argv1=config.argv1,
        stop_symbol=config.stop_symbol,
        capture_start_addr=config.capture_start_addr,
        loader_max_steps=config.loader_max_steps,
        capture_ranges=(
            binary_ranges if binary_ranges is not None else config.capture_ranges
        ),
        stop_addr=config.stop_addr,
        memory_patches=config.memory_patches,
        stack_payload=config.stack_payload,
    )
    if config.arch_bits == 32 and config.stack_base > 0xFFFFFFFF:
        # Ajuste la pile 32-bit si nécessaire.
        config = TraceConfig(
            base=config.base,
            stack_base=0xBFF00000,
            stack_size=config.stack_size,
            max_steps=config.max_steps,
            stack_entries=config.stack_entries,
            arch_bits=config.arch_bits,
            interp_base=config.interp_base,
            start_interp=config.start_interp,
            stdin_data=config.stdin_data,
            buffer_offset=config.buffer_offset,
            buffer_size=config.buffer_size,
            start_symbol=config.start_symbol,
            argv1=config.argv1,
            stop_symbol=config.stop_symbol,
            capture_start_addr=config.capture_start_addr,
            loader_max_steps=config.loader_max_steps,
            capture_ranges=config.capture_ranges,
            stop_addr=config.stop_addr,
            memory_patches=config.memory_patches,
            stack_payload=config.stack_payload,
        )
    # Initialise la pile et prépare argc/argv/auxv.
    init_stack(uc, config)
    auxv = [
        (3, phdr_vaddr),  # AT_PHDR
        (4, header["phentsize"]),  # AT_PHENT
        (5, header["phnum"]),  # AT_PHNUM
        (6, page_size),  # AT_PAGESZ
        (7, base + entry),  # AT_BASE (placeholder, overwritten below)
        (9, base + entry),  # AT_ENTRY
    ]
    if interp_base is not None:
        auxv = [(k, interp_base if k == 7 else v) for k, v in auxv]
    else:
        auxv = [(k, 0 if k == 7 else v) for k, v in auxv]
    argv0 = binary_path or "a.out"
    argv = [argv0]
    if config.argv1 is not None:
        argv.append(config.argv1)
    sp = build_initial_stack(uc, config, argv, [], auxv)
    main_word_size = 8 if config.arch_bits == 64 else 4
    argc_value = len(argv)
    argv_ptr = sp + main_word_size
    envp_ptr = argv_ptr + ((argc_value + 1) * main_word_size)
    inject_stack_payload(uc, sp, config)
    sp_reg = get_pc_sp(config.arch_bits)[1]
    uc.reg_write(sp_reg, sp)

    rbp_reg = get_rbp(config.arch_bits)
    reg_order = get_reg_order(config.arch_bits)
    external_state: dict = {}
    collector = SnapshotCollector(
        config,
        reg_order,
        sp_reg,
        rbp_reg,
        get_pc_sp(config.arch_bits)[0],
        external_state=external_state,
    )
    syscalls = ReadSyscallEmulator(config)
    plt_symbols = _load_plt_symbols(binary_path, base if is_pie else 0)
    uc.hook_add(UC_HOOK_CODE, collector.hook_code)
    uc.hook_add(UC_HOOK_MEM_READ, collector.hook_mem_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, collector.hook_mem_write)
    external_skip_state = _install_external_fetch_skip_hook(
        uc,
        config,
        config.arch_bits,
        plt_symbols,
        shared_state=external_state,
    )
    uc.hook_add(UC_HOOK_INTR, syscalls.hook_intr)
    uc.hook_add(UC_HOOK_INSN, syscalls.hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    # Détermine le point de départ (symbole, interp, ou entry).
    start_addr = config.base
    symbol_addr = None
    if binary_path and config.start_symbol:
        symbol_addr = resolve_symbol_addr(
            binary_path,
            config.start_symbol,
            base if is_pie else 0,
        )
        if symbol_addr is not None:
            start_addr = symbol_addr
    if binary_path and config.stop_symbol:
        stop_addr = resolve_symbol_addr(
            binary_path,
            config.stop_symbol,
            base if is_pie else 0,
        )
        if stop_addr is not None:
            config.stop_addr = stop_addr
    if config.start_interp and interp_entry is not None:
        start_addr = interp_entry
    elif symbol_addr is not None:
        _prepare_main_entry_context(
            uc,
            config.arch_bits,
            sp_reg,
            config.start_symbol,
            argc_value,
            argv_ptr,
            envp_ptr,
        )
    end_addr = 0xFFFFFFFF if config.arch_bits == 32 else 0xFFFFFFFFFFFFFFFF
    # Lance l'émulation; tente fallback sur l'interpréteur si l'entry échoue.
    error: Optional[str] = None
    try:
        uc.emu_start(start_addr, end_addr)
    except UcError as exc:
        error = str(exc)
        if (
            not config.start_interp
            and interp_entry is not None
            and not collector.snapshots
            and "UC_ERR_FETCH_UNMAPPED" in error
        ):
            try:
                uc.emu_start(interp_entry, end_addr)
                error = None
            except UcError as exc2:
                error = str(exc2)
    finally:
        collector.finalize_pending(uc)

    # Enrichit snapshots avec file/line/func via addr2line si dispo.
    if binary_path and collector.snapshots and shutil.which("addr2line"):
        addr_map = addr2line_map(
            binary_path,
            [snap["rip"] for snap in collector.snapshots if "rip" in snap],
            base if is_pie else 0,
        )
        for snap in collector.snapshots:
            info = addr_map.get(snap.get("rip"))
            if info:
                snap["file"] = info.get("file")
                snap["line"] = info.get("line")
                snap["func"] = info.get("func")

    return {
        "snapshots": collector.snapshots,
        "meta": {
            "steps": collector.step,
            "error": error,
            "base": hex(base),
            "stack_base": hex(config.stack_base),
            "stack_size": config.stack_size,
            "arch_bits": config.arch_bits,
            "elf_entry": hex(entry),
            "elf_pie": is_pie,
            "elf_interp": interp_path,
            "elf_interp_started": bool(
                config.start_interp and interp_entry is not None
            ),
            "word_size": 8 if config.arch_bits == 64 else 4,
            "endian": "little",
            "buffer_offset": config.buffer_offset,
            "buffer_size": config.buffer_size,
            "start_symbol": config.start_symbol,
            "stop_symbol": config.stop_symbol,
            "argv1": config.argv1,
            "stdin_len": len(config.stdin_data),
            "skipped_external_calls": external_skip_state["skipped_external"],
            "simulated_strcpy_calls": external_skip_state["simulated_strcpy"],
            "simulated_external_calls": external_skip_state.get(
                "simulated_by_symbol", {}
            ),
            "stop_addr": (
                hex(config.stop_addr) if config.stop_addr is not None else None
            ),
        },
    }


def trace_binary(
    code_bytes: bytes, config: TraceConfig, binary_path: Optional[str]
) -> Dict[str, object]:
    """@brief Selectionne la trace ELF ou raw/Mach-O.
    @param code_bytes Bytes du binaire.
    @param config Configuration de trace.
    @param binary_path Chemin du binaire (optionnel).
    @return Dictionnaire {snapshots, meta}.
    """
    if is_elf(code_bytes):
        return trace_elf(code_bytes, config, binary_path)
    return trace_raw(code_bytes, config, binary_path)
