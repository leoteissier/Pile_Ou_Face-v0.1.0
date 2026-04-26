"""Tests pour backends.static.bindiff."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static import bindiff
from backends.static.arch import RISCV_ADAPTER


def _import_make_elf():
    p = Path(__file__).parent / "fixtures" / "make_elf.py"
    spec = importlib.util.spec_from_file_location("make_elf", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_minimal_elf


make_minimal_elf = _import_make_elf()


def run(args):
    """Run bindiff.py as a subprocess and return parsed JSON output."""
    r = subprocess.run(
        [sys.executable, "backends/static/bindiff.py"] + args,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    if not r.stdout.strip():
        raise RuntimeError(
            f"bindiff.py produced no output:\n"
            f"stdout={r.stdout!r}\nstderr={r.stderr!r}"
        )
    return json.loads(r.stdout)


class TestBindiff(unittest.TestCase):
    """Tests du diff binaire de bindiff.py."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.binary = str(Path(self.tmp) / "test.elf")
        make_minimal_elf(self.binary)

    def test_output_schema(self):
        """Vérifie la structure de base de la sortie JSON."""
        data = run(["--binary-a", self.binary, "--binary-b", self.binary])
        self.assertTrue(data.get("ok"), msg=f"ok is not True: {data}")
        self.assertIn("functions", data)
        self.assertIsInstance(data["functions"], list)
        self.assertIn("stats", data)
        self.assertIsInstance(data["stats"], dict)
        self.assertIn("meta", data)
        self.assertIsInstance(data["meta"], dict)
        for key in ("module", "timestamp", "threshold"):
            self.assertIn(key, data["meta"], msg=f"meta missing key: {key}")

    def test_identical_binary(self):
        """Comparer un binaire avec lui-même → 0 modified, added, removed."""
        data = run(["--binary-a", self.binary, "--binary-b", self.binary])
        self.assertTrue(data.get("ok"), msg=f"ok is not True: {data}")
        stats = data["stats"]
        self.assertEqual(stats.get("modified", -1), 0)
        self.assertEqual(stats.get("added", -1), 0)
        self.assertEqual(stats.get("removed", -1), 0)

    def test_identical_functions_have_no_diff(self):
        """Toutes les fonctions doivent être identiques et sans diff."""
        data = run(["--binary-a", self.binary, "--binary-b", self.binary])
        self.assertTrue(data.get("ok"), msg=f"ok is not True: {data}")
        for fn in data["functions"]:
            self.assertEqual(fn.get("status"), "identical")
            self.assertEqual(fn.get("diff"), [])

    def test_function_entry_schema(self):
        """Chaque entrée de fonction doit avoir les champs requis."""
        data = run(["--binary-a", self.binary, "--binary-b", self.binary])
        self.assertTrue(data.get("ok"), msg=f"ok is not True: {data}")
        for fn in data["functions"]:
            for key in ("name", "addr_a", "addr_b", "status", "similarity", "diff"):
                self.assertIn(key, fn, msg=f"Function entry missing key: {key}")

    def test_graceful_on_bad_path(self):
        """Un chemin invalide → ok=False avec error et functions=[]."""
        data = run(["--binary-a", "/nonexistent", "--binary-b", "/nonexistent"])
        self.assertFalse(data.get("ok"))
        self.assertIn("error", data)
        self.assertEqual(data.get("functions"), [])
        self.assertIn("meta", data)

    def test_threshold_respected(self):
        """Avec threshold=1.0 et le même binaire → ok=True."""
        data = run(
            ["--binary-a", self.binary, "--binary-b", self.binary, "--threshold", "1.0"]
        )
        self.assertTrue(data.get("ok"), msg=f"ok is not True: {data}")

    def test_arch_mode_uses_central_arch_detector(self):
        """La résolution d'architecture doit passer par backends.static.arch."""
        fake_info = SimpleNamespace(capstone_tuple=(123, 456))
        with mock.patch.object(bindiff, "capstone", object()), mock.patch.object(
            bindiff, "lief", object()
        ), mock.patch.object(
            bindiff, "detect_binary_arch", return_value=fake_info
        ) as detect:
            self.assertEqual(bindiff._get_arch_mode(object()), (123, 456))
        detect.assert_called_once()

    def test_disasm_stops_on_architecture_return(self):
        """Les retours non-x86, comme RISC-V ret, terminent bien la fonction."""
        fake_cs = SimpleNamespace(
            disasm=lambda _code, _base: iter(
                [
                    SimpleNamespace(address=0x1000, mnemonic="addi", op_str="sp, sp, -16"),
                    SimpleNamespace(address=0x1004, mnemonic="ret", op_str=""),
                    SimpleNamespace(address=0x1008, mnemonic="addi", op_str="a0, a0, 1"),
                ]
            )
        )
        arch_info = SimpleNamespace(adapter=RISCV_ADAPTER)
        with mock.patch.object(
            bindiff, "_get_section_bytes", return_value=(b"\x00" * 12, 0x1000)
        ):
            insns = bindiff._disasm_func(object(), fake_cs, arch_info, 0x1000)
        self.assertEqual([insn["mnem"] for insn in insns], ["addi", "ret"])

    def test_basic_blocks_use_architecture_branch_semantics(self):
        """Les branches RISC-V doivent couper les basic blocks."""
        arch_info = SimpleNamespace(adapter=RISCV_ADAPTER)
        insns = [
            {"mnem": "addi", "op_str": "", "norm": "addi sp, sp, IMM", "asm": "addi"},
            {"mnem": "bnez", "op_str": "a0, 0x1010", "norm": "bnez a0, ADDR", "asm": "bnez"},
            {"mnem": "ret", "op_str": "", "norm": "ret", "asm": "ret"},
        ]
        self.assertEqual(
            bindiff._build_basic_blocks(insns, arch_info),
            [("addi sp, sp, IMM", "bnez a0, ADDR"), ("ret",)],
        )


if __name__ == "__main__":
    unittest.main()
