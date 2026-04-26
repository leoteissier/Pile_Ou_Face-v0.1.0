import sys, unittest, tempfile, os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.rop_gadgets import (
    find_gadgets,
    _classify_gadget,
    _detect_arch_for_file,
    _iter_executable_regions,
    _modified_registers,
    _scan_for_rets,
)
from backends.static import rop_gadgets as rop_module


class TestRopGadgets(unittest.TestCase):

    def test_nonexistent_returns_empty(self):
        r = find_gadgets("/nonexistent")
        self.assertEqual(r, [])

    def test_result_structure(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x90" * 10 + b"\xc3")
            path = f.name
        try:
            r = find_gadgets(path)
            for g in r:
                for field in ("addr", "instructions", "type"):
                    self.assertIn(field, g)
        finally:
            os.unlink(path)

    def test_ret_detected(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x90\x90\x90\x90\x90\xc3")
            path = f.name
        try:
            rets = _scan_for_rets(Path(path).read_bytes())
            self.assertIn(5, rets)
        finally:
            os.unlink(path)

    def test_classify_pop_ret(self):
        insns = ["pop rax", "ret"]
        t = _classify_gadget(insns)
        self.assertEqual(t, "pop_ret")

    def test_classify_syscall(self):
        insns = ["syscall", "ret"]
        t = _classify_gadget(insns)
        self.assertEqual(t, "syscall")

    def test_classify_pivot(self):
        insns = ["xchg rsp, rax", "ret"]
        t = _classify_gadget(insns)
        self.assertEqual(t, "pivot")

    def test_classify_generic(self):
        insns = ["add rax, rbx", "ret"]
        t = _classify_gadget(insns)
        self.assertEqual(t, "arithmetic")

    def test_classify_multi_arch_pop_and_load_store(self):
        self.assertEqual(_classify_gadget(["ldp x29, x30, [sp], #0x10", "ret"]), "pivot")
        self.assertEqual(_classify_gadget(["lw ra, 8(sp)", "jr ra"]), "pop_ret")
        self.assertEqual(_classify_gadget(["str x0, [sp, #0x8]", "ret"]), "load_store")
        self.assertEqual(_classify_gadget(["addi sp, sp, 0x20", "ret"]), "pivot")

    def test_modified_registers_x86_and_multi_arch(self):
        self.assertEqual(_modified_registers(["pop rax", "ret"]), ["rax"])
        self.assertEqual(_modified_registers(["add rax, rbx", "ret"]), ["rax"])
        self.assertEqual(_modified_registers(["ldp x29, x30, [sp], #0x10", "ret"]), ["x29", "x30"])
        self.assertEqual(_modified_registers(["addi a0, a0, 1", "ret"]), ["a0"])
        self.assertEqual(_modified_registers(["sw a0, 8(sp)", "jr ra"]), [])

    def test_max_insns_respected(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x90" * 10 + b"\xc3")
            path = f.name
        try:
            r = find_gadgets(path, max_insns=3)
            for g in r:
                self.assertLessEqual(len(g["instructions"]), 3)
        finally:
            os.unlink(path)

    def test_no_gadgets_in_zeros(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 64)
            path = f.name
        try:
            r = find_gadgets(path)
            self.assertEqual(r, [])
        finally:
            os.unlink(path)

    def test_non_x86_does_not_scan_x86_ret_bytes(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x90\x90\xc3")
            path = f.name
        try:
            r = find_gadgets(path, arch="aarch64")
            self.assertEqual(r, [])
        finally:
            os.unlink(path)

    def test_auto_arch_uses_binary_detection_when_requested(self):
        fake_info = SimpleNamespace(raw_name="riscv64")
        with mock.patch.object(rop_module, "detect_binary_arch_from_path", return_value=fake_info):
            self.assertIs(_detect_arch_for_file("/tmp/demo.elf", "auto"), fake_info)

    def test_explicit_arch_skips_binary_detection(self):
        with mock.patch.object(rop_module, "detect_binary_arch_from_path") as detect:
            info = _detect_arch_for_file("/tmp/demo.elf", "riscv64")
        self.assertIsNotNone(info)
        self.assertEqual(info.key, "riscv64")
        detect.assert_not_called()

    def test_iter_executable_regions_reads_only_exec_sections(self):
        class FakeElfBinary:
            pass

        exec_flag = object()
        fake_lief = SimpleNamespace(
            ELF=SimpleNamespace(
                Binary=FakeElfBinary,
                Section=SimpleNamespace(FLAGS=SimpleNamespace(EXECINSTR=exec_flag)),
            ),
            PE=SimpleNamespace(Binary=type("PEBinary", (), {}), Section=SimpleNamespace(CHARACTERISTICS=SimpleNamespace(CNT_CODE=object()))),
            MachO=SimpleNamespace(Binary=type("MachOBinary", (), {})),
        )
        binary = FakeElfBinary()
        binary.sections = [
            SimpleNamespace(virtual_address=0x1000, content=[0x90, 0xC3], flags_list=[exec_flag]),
            SimpleNamespace(virtual_address=0x2000, content=[0x00, 0x00], flags_list=[]),
        ]
        fake_lief.parse = mock.Mock(return_value=binary)

        with mock.patch.object(rop_module, "lief", fake_lief):
            regions = _iter_executable_regions("/tmp/demo.elf")

        self.assertEqual(regions, [(0x1000, b"\x90\xc3")])

    def test_x86_native_gadget_addresses_use_executable_region_vaddr(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 16)
            path = f.name
        try:
            with mock.patch.object(rop_module, "_iter_executable_regions", return_value=[(0x401000, b"\x90\xc3")]), \
                 mock.patch.object(rop_module, "_disasm_bytes", return_value=["nop", "ret"]):
                gadgets = find_gadgets(path, arch="x86_64")

            self.assertTrue(gadgets)
            self.assertEqual(gadgets[0]["addr"], "0x401000")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
