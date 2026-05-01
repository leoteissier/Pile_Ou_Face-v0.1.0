"""Tests for the dynamic semantic stack model."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.pipeline.stack_model import (
    _guess_buffer_region,
    _overflow_summary,
    build_dynamic_analysis,
)


def _hex_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in data)


class TestDynamicStackModel(unittest.TestCase):

    def test_compat_imports_reexport_moved_symbols(self):
        from backends.dynamic.stack_model import build_dynamic_analysis as compat_build
        from backends.dynamic.engine.unicorn.config import TraceConfig
        from backends.dynamic.run_pipeline import TraceConfig as pipeline_compat_config

        self.assertIs(compat_build, build_dynamic_analysis)
        self.assertIs(pipeline_compat_config, TraceConfig)

    def test_guess_buffer_region_prefers_static_var_when_trace_offset_disagrees(self):
        bp = 0x1000
        frame = {
            "vars": [
                {"name": "buffer", "offset": -0x50, "size": 64, "source": "auto"},
                {"name": "modified", "offset": -4, "size": 4, "source": "auto"},
            ]
        }
        meta = {
            "buffer_offset": -0x40,
            "buffer_size": 64,
        }

        region = _guess_buffer_region(frame, bp, meta)

        self.assertIsNotNone(region)
        self.assertEqual(region["start"], bp - 0x50)
        self.assertEqual(region["end"], bp - 0x10)
        self.assertEqual(region["label"], "buffer")
        self.assertEqual(region["source"], "heuristic")

    def test_runtime_write_infers_buffer_and_detects_control_overwrite(self):
        word = 8
        rbp = 0x1000
        rsp = 0x0FB8
        window_start = 0x0FB8
        buffer_start = 0x0FC0
        write_size = 80
        payload = b"A" * write_size
        window = bytearray(b"\x00" * 0x60)
        write_offset = buffer_start - window_start
        window[write_offset : write_offset + write_size] = payload

        snapshot = {
            "step": 1,
            "instr": "call 0x401030",
            "instruction": {
                "address": "0x401020",
                "size": 5,
                "bytes": "e8 0b 00 00 00",
                "mnemonic": "call",
                "operands": "0x401030",
                "text": "call 0x401030",
            },
            "cpu": {
                "arch": "x86_64",
                "word_size": word,
                "endian": "little",
                "aliases": {"sp": "rsp", "bp": "rbp", "fp": "rbp", "ip": "rip", "lr": None},
                "before": {
                    "registers": {
                        "rsp": hex(rsp),
                        "rbp": hex(rbp),
                        "rip": "0x401020",
                    }
                },
                "after": {
                    "registers": {
                        "rsp": hex(rsp),
                        "rbp": hex(rbp),
                        "rip": "0x401025",
                    }
                },
            },
            "memory": {
                "window_start": hex(window_start),
                "window_bytes": _hex_bytes(window),
                "writes": [
                    {
                        "addr": hex(buffer_start),
                        "size": write_size,
                        "bytes": _hex_bytes(payload),
                        "source": "external",
                    }
                ],
                "reads": [],
            },
            "effects": {
                "kind": "call",
                "call_target": "0x401030",
                "external_simulated": True,
                "external_symbol": "strcpy",
            },
            "registers": [
                {"name": "rbp", "value": hex(rbp), "pos": 0},
                {"name": "rsp", "value": hex(rsp), "pos": 1},
                {"name": "rip", "value": "0x401020", "pos": 2},
            ],
            "stack": [],
        }
        meta = {
            "arch_bits": 64,
            "word_size": word,
            "stack_base": hex(0x0F00),
            "stack_size": 0x200,
            "binary": str(__file__),
        }
        disasm = [{"addr": "0x401020", "text": "call 0x401030"}, {"addr": "0x401030", "text": "ret"}]

        analysis = build_dynamic_analysis([snapshot], meta, str(__file__), disasm)
        step = analysis["1"]

        self.assertEqual(step["buffer"]["start"], hex(buffer_start))
        self.assertEqual(step["buffer"]["size"], rbp - buffer_start)
        self.assertTrue(step["overflow"]["active"])
        self.assertEqual(step["overflow"]["controlRisk"], "return_address")
        self.assertIn("saved_bp", step["overflow"]["reached"])
        self.assertIn("return_address", step["overflow"]["reached"])
        self.assertTrue(any("Overflow:" in bullet for bullet in step["explanationBullets"]))

    def test_leave_keeps_frame_control_addresses_on_last_valid_bp(self):
        word = 4
        ebp = 0x1000
        esp = 0x0FC0
        window_start = 0x0FA0
        window = bytearray(b"\x00" * 0x80)
        buffer_start = ebp - 0x40
        write_offset = buffer_start - window_start
        window[write_offset : write_offset + 64] = b"A" * 64
        saved_bp_offset = ebp - window_start
        window[saved_bp_offset : saved_bp_offset + 4] = b"BBBB"
        ret_offset = (ebp + 4) - window_start
        window[ret_offset : ret_offset + 4] = b"CCCC"
        arg_offset = (ebp + 8) - window_start
        window[arg_offset : arg_offset + 4] = b"\x96\x91\x04\x08"

        step1 = {
            "step": 1,
            "func": "main",
            "instr": "mov eax, 0",
            "instruction": {
                "address": "0x401000",
                "size": 3,
                "bytes": "b8 00 00",
                "mnemonic": "mov",
                "operands": "eax, 0",
                "text": "mov eax, 0",
            },
            "cpu": {
                "arch": "x86",
                "word_size": word,
                "endian": "little",
                "aliases": {"sp": "esp", "bp": "ebp", "fp": "ebp", "ip": "eip", "lr": None},
                "before": {"registers": {"esp": hex(esp), "ebp": hex(ebp), "eip": "0x401000"}},
                "after": {"registers": {"esp": hex(esp), "ebp": hex(ebp), "eip": "0x401003"}},
            },
            "memory": {
                "window_start": hex(window_start),
                "window_bytes": _hex_bytes(window),
                "writes": [],
                "reads": [],
            },
            "effects": {"kind": "write"},
            "registers": [],
            "stack": [],
        }

        step2 = {
            "step": 2,
            "func": "main",
            "instr": "leave",
            "instruction": {
                "address": "0x401003",
                "size": 1,
                "bytes": "c9",
                "mnemonic": "leave",
                "operands": "",
                "text": "leave",
            },
            "cpu": {
                "arch": "x86",
                "word_size": word,
                "endian": "little",
                "aliases": {"sp": "esp", "bp": "ebp", "fp": "ebp", "ip": "eip", "lr": None},
                "before": {"registers": {"esp": hex(esp), "ebp": hex(ebp), "eip": "0x401003"}},
                "after": {
                    "registers": {
                        "esp": hex(ebp + 4),
                        "ebp": "0x42424242",
                        "eip": "0x401004",
                    }
                },
            },
            "memory": {
                "window_start": hex(window_start),
                "window_bytes": _hex_bytes(window),
                "writes": [],
                "reads": [],
            },
            "effects": {"kind": "write"},
            "registers": [],
            "stack": [],
        }

        meta = {
            "arch_bits": 32,
            "word_size": word,
            "stack_base": hex(0x0F00),
            "stack_size": 0x400,
            "buffer_offset": -0x40,
            "buffer_size": 64,
            "binary": str(__file__),
        }
        disasm = [
            {"addr": "0x401000", "text": "mov eax, 0"},
            {"addr": "0x401003", "text": "leave"},
            {"addr": "0x401004", "text": "ret"},
        ]

        analysis = build_dynamic_analysis([step1, step2], meta, str(__file__), disasm)
        leave_step = analysis["2"]

        self.assertEqual(leave_step["frame"]["basePointer"], hex(ebp))
        self.assertEqual(leave_step["frame"]["registerBasePointer"], "0x42424242")
        self.assertEqual(leave_step["control"]["savedBpAddr"], hex(ebp))
        self.assertEqual(leave_step["control"]["retAddrAddr"], hex(ebp + word))
        self.assertEqual(leave_step["control"]["retValue"], "0x43434343")

    def test_overflow_summary_ignores_control_flags_without_crossing_write(self):
        analysis = {
            "buffer": {
                "name": "buffer",
                "start": "0xfc0",
                "end": "0x1000",
                "size": 64,
            },
            "control": {
                "savedBpAddr": "0x1000",
                "retAddrAddr": "0x1008",
            },
            "frame": {
                "slots": [
                    {"role": "buffer", "start": "0xfc0", "end": "0x1000", "recentWrite": True, "changed": True},
                    {"role": "saved_bp", "start": "0x1000", "end": "0x1008", "corrupted": True},
                    {"role": "return_address", "start": "0x1008", "end": "0x1010", "corrupted": True},
                ]
            },
            "delta": {
                "writes": [
                    {"addr": "0xfc0", "size": 25, "bytes": _hex_bytes(b"A" * 25)}
                ]
            },
        }

        overflow = _overflow_summary(analysis)

        self.assertIsNotNone(overflow)
        self.assertFalse(overflow["active"])
        self.assertEqual(overflow["progressBytes"], 0)


if __name__ == "__main__":
    unittest.main()
