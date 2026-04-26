"""Fixtures réutilisables pour les blobs bruts / shellcodes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backends.static.disasm import disassemble_with_capstone

RAW_X64_CALL_BLOB = bytes.fromhex(
    "554889e5"
    "e807000000"
    "c3"
    "909090909090"
    "554889e5"
    "c3"
)

RAW_ARM64_CALL_BLOB = bytes.fromhex(
    "fd7bbfa9"  # stp x29, x30, [sp, #-0x10]!
    "fd030091"  # mov x29, sp
    "03000094"  # bl #target
    "fd7bc1a8"  # ldp x29, x30, [sp], #0x10
    "c0035fd6"  # ret
    "c0035fd6"  # target: ret
)

RAW_ARM32_CALL_BLOB = bytes.fromhex(
    "00482de9"  # push {fp, lr}
    "04b08de2"  # add fp, sp, #4
    "000000eb"  # bl #target
    "0088bde8"  # pop {fp, pc}
    "1eff2fe1"  # target: bx lr
)

RAW_X64_PROFILE = {
    "arch": "i386:x86-64",
    "base_addr": "0x500000",
    "endian": "little",
}

RAW_ARM64_PROFILE = {
    "arch": "aarch64",
    "base_addr": "0x600000",
    "endian": "little",
}

RAW_ARM32_PROFILE = {
    "arch": "arm",
    "base_addr": "0x700000",
    "endian": "little",
}


def _write_raw_fixture(
    tmpdir: str | Path,
    *,
    stem: str,
    blob: bytes,
    raw_profile: dict[str, str],
    call_site_addr: str,
    target_addr: str,
) -> dict[str, Any]:
    root = Path(tmpdir)
    blob_path = root / f"{stem}.bin"
    mapping_path = root / f"{stem}.mapping.json"
    asm_path = root / f"{stem}.disasm.asm"

    blob_path.write_bytes(blob)
    lines = disassemble_with_capstone(
        str(blob_path),
        raw_arch=raw_profile["arch"],
        raw_base_addr=raw_profile["base_addr"],
        raw_endian=raw_profile["endian"],
    ) or []

    mapping = {
        "path": str(asm_path),
        "binary": str(blob_path),
        "raw": dict(raw_profile),
        "lines": lines,
    }
    mapping_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")

    return {
        "blob_path": blob_path,
        "mapping_path": mapping_path,
        "asm_path": asm_path,
        "lines": lines,
        "raw": dict(raw_profile),
        "entry_addr": raw_profile["base_addr"],
        "call_site_addr": call_site_addr,
        "target_addr": target_addr,
    }


def write_raw_x64_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode x86-64 brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_x64_call",
        blob=RAW_X64_CALL_BLOB,
        raw_profile=RAW_X64_PROFILE,
        call_site_addr="0x500004",
        target_addr="0x500010",
    )


def write_raw_arm64_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode ARM64 brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_arm64_call",
        blob=RAW_ARM64_CALL_BLOB,
        raw_profile=RAW_ARM64_PROFILE,
        call_site_addr="0x600008",
        target_addr="0x600014",
    )


def write_raw_arm32_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode ARM32 brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_arm32_call",
        blob=RAW_ARM32_CALL_BLOB,
        raw_profile=RAW_ARM32_PROFILE,
        call_site_addr="0x700008",
        target_addr="0x700010",
    )
