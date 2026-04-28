"""Targeted tests for scanf emulation in the Unicorn tracer."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.engine.unicorn.tracer import _simulate_symbol_with_args


class _FakeUc:
    def __init__(self, size: int = 0x4000) -> None:
        self._memory = bytearray(size)

    def mem_read(self, addr: int, size: int) -> bytes:
        return bytes(self._memory[addr : addr + size])

    def mem_write(self, addr: int, data: bytes) -> None:
        blob = bytes(data)
        self._memory[addr : addr + len(blob)] = blob


def _write_u32(uc: _FakeUc, addr: int, value: int) -> None:
    uc.mem_write(addr, int(value).to_bytes(4, "little", signed=False))


class TestTracerScanf(unittest.TestCase):

    def test_scanf_reads_string_from_stdin_into_destination(self):
        uc = _FakeUc()
        fmt_addr = 0x100
        dst_addr = 0x200
        sp = 0x300

        uc.mem_write(fmt_addr, b"%s\x00")
        _write_u32(uc, sp + 0, fmt_addr)
        _write_u32(uc, sp + 4, dst_addr)

        state = {
            "stdin_data": b"AAAA BBBB\n",
            "stdin_pos": 0,
            "current_external_event": {"reads": [], "writes": []},
        }

        assigned = _simulate_symbol_with_args(
            uc,
            32,
            "__isoc99_scanf",
            sp,
            4,
            state,
        )

        self.assertEqual(assigned, 1)
        self.assertEqual(uc.mem_read(dst_addr, 5), b"AAAA\x00")
        self.assertEqual(state["stdin_pos"], 4)
        self.assertEqual(
            state["current_external_event"]["writes"],
            [
                {
                    "addr": hex(dst_addr),
                    "size": 5,
                    "bytes": "41 41 41 41 00",
                    "source": "external",
                }
            ],
        )

    def test_scanf_accepts_isoc23_symbol_alias(self):
        uc = _FakeUc()
        fmt_addr = 0x100
        dst_addr = 0x200
        sp = 0x300

        uc.mem_write(fmt_addr, b"%s\x00")
        _write_u32(uc, sp + 0, fmt_addr)
        _write_u32(uc, sp + 4, dst_addr)

        state = {
            "stdin_data": b"AAAA\n",
            "stdin_pos": 0,
            "current_external_event": {"reads": [], "writes": []},
        }

        assigned = _simulate_symbol_with_args(
            uc,
            32,
            "__isoc23_scanf",
            sp,
            4,
            state,
        )

        self.assertEqual(assigned, 1)
        self.assertEqual(uc.mem_read(dst_addr, 5), b"AAAA\x00")
        self.assertEqual(state["stdin_pos"], 4)

    def test_scanf_supports_multiple_bounded_string_conversions(self):
        uc = _FakeUc()
        fmt_addr = 0x100
        dst1_addr = 0x200
        dst2_addr = 0x240
        sp = 0x300

        uc.mem_write(fmt_addr, b"%4s %2s\x00")
        _write_u32(uc, sp + 0, fmt_addr)
        _write_u32(uc, sp + 4, dst1_addr)
        _write_u32(uc, sp + 8, dst2_addr)

        state = {
            "stdin_data": b"WXYZ UV\n",
            "stdin_pos": 0,
            "current_external_event": {"reads": [], "writes": []},
        }

        assigned = _simulate_symbol_with_args(
            uc,
            32,
            "scanf",
            sp,
            4,
            state,
        )

        self.assertEqual(assigned, 2)
        self.assertEqual(uc.mem_read(dst1_addr, 5), b"WXYZ\x00")
        self.assertEqual(uc.mem_read(dst2_addr, 3), b"UV\x00")
        self.assertEqual(state["stdin_pos"], 7)
        self.assertEqual(len(state["current_external_event"]["writes"]), 2)


if __name__ == "__main__":
    unittest.main()
