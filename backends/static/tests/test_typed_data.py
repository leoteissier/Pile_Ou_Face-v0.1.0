# backends/static/tests/test_typed_data.py
import os
import sys
import json
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)
from backends.static.tests.fixtures.make_elf import make_minimal_elf
from backends.static.structs import parse_struct_definitions
from backends.static.typed_data import _decode_struct_entries, _resolve_struct_location

try:
    import lief as _lief
    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


def run_td(binary, section=None, type_=None, page=None, raw_base_addr=None):
    args = [sys.executable, "backends/static/typed_data.py", "--binary", binary]
    if section:
        args += ["--section", section]
    if type_:
        args += ["--type", type_]
    if page is not None:
        args += ["--page", str(page)]
    if raw_base_addr is not None:
        args += ["--raw-base-addr", str(raw_base_addr)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=ROOT)
    return json.loads(r.stdout)


class TestTypedData(unittest.TestCase):

    def test_error_on_missing(self):
        result = run_td("/nonexistent")
        self.assertIsNotNone(result.get("error"))

    def test_lists_sections(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_td(elf)
            self.assertIn("sections", result)
            self.assertIsInstance(result["sections"], list)

    def test_u8_type_produces_entries(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_td(elf, type_="u8")
            self.assertIn("entries", result)
            self.assertIsInstance(result["entries"], list)
            if result["entries"]:
                entry = result["entries"][0]
                self.assertIn("offset", entry)
                self.assertIn("decoded", entry)
                self.assertIn("hex", entry)
                self.assertIn("addr", entry)

    def test_raw_blob_fallback_lists_raw_section_and_strings(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00hello raw\x00\x01\x02")
            raw_path = f.name
        try:
            result = run_td(raw_path, section="raw", type_="str", raw_base_addr="0x417000")
            self.assertIsNone(result.get("error"))
            self.assertEqual(result.get("source"), "raw")
            self.assertEqual(result.get("sections"), ["raw"])
            self.assertEqual(result.get("section"), "raw")
            self.assertTrue(any(entry.get("decoded") == '"hello raw"' for entry in result.get("entries", [])))
            self.assertTrue(any(entry.get("addr") == "0x417001" for entry in result.get("entries", [])))
        finally:
            os.unlink(raw_path)

    def test_raw_blob_fallback_rejects_unknown_section(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"abc")
            raw_path = f.name
        try:
            result = run_td(raw_path, section=".data", type_="u8")
            self.assertIsNotNone(result.get("error"))
            self.assertEqual(result.get("sections"), ["raw"])
        finally:
            os.unlink(raw_path)

    def test_output_has_pagination_fields_on_success(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_td(elf, page=0)
            if not result.get("error"):
                self.assertIn("page", result)
                self.assertIn("page_size", result)
                self.assertIn("total_entries", result)

    def test_decode_struct_entries_renders_fields(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Demo {
              uint32_t magic;
              char name[4];
              uint16_t count;
            } Demo;
            """
        )
        data = bytes.fromhex("44 33 22 11 41 42 43 00 02 00 00 00")
        result = _decode_struct_entries(data, 0x401000, "Demo", 0, 8, definitions)
        self.assertEqual(result["name"], "Demo")
        self.assertEqual(result["fields"][0]["decoded"], "287454020")
        self.assertEqual(result["fields"][1]["decoded"], '"ABC"')
        self.assertEqual(result["fields"][2]["decoded"], "2")
        self.assertEqual(result["fields"][2]["addr"], "0x401008")

    def test_resolve_struct_location_from_vaddr(self):
        binary = SimpleNamespace(
            sections=[
                SimpleNamespace(name=".text", content=[0x90] * 16, virtual_address=0x401000, flags=0x4),
                SimpleNamespace(name=".data", content=[0x00] * 32, virtual_address=0x402000, flags=0),
            ]
        )
        section, offset = _resolve_struct_location(binary, None, 0, 0x40200C)
        self.assertEqual(section, ".data")
        self.assertEqual(offset, 0x0C)

    def test_resolve_struct_location_rejects_addr_outside_data_sections(self):
        binary = SimpleNamespace(
            sections=[
                SimpleNamespace(name=".text", content=[0x90] * 16, virtual_address=0x401000, flags=0x4),
                SimpleNamespace(name=".data", content=[0x00] * 16, virtual_address=0x402000, flags=0),
            ]
        )
        with self.assertRaises(ValueError):
            _resolve_struct_location(binary, None, 0, 0x403000)

    def test_decode_struct_entries_supports_enum_and_union(self):
        definitions = parse_struct_definitions(
            """
            typedef enum Mode {
              MODE_NONE,
              MODE_READY = 2
            } Mode;

            typedef union Payload {
              uint32_t raw;
              char text[4];
            } Payload;

            typedef struct Packet {
              Mode mode;
              Payload payload;
            } Packet;
            """
        )
        data = bytes.fromhex("02 00 00 00 41 42 43 00")
        result = _decode_struct_entries(data, 0x401000, "Packet", 0, 8, definitions)
        self.assertEqual(result["kind"], "struct")
        self.assertEqual(result["fields"][0]["decoded"], "MODE_READY (2)")
        self.assertEqual(result["fields"][0]["field_kind"], "enum")
        self.assertIn("union Payload", result["fields"][1]["decoded"])
        self.assertIn('text="ABC"', result["fields"][1]["decoded"])

    def test_decode_union_entries_reuses_same_address_for_members(self):
        definitions = parse_struct_definitions(
            """
            typedef union Payload {
              uint32_t raw;
              char text[4];
            } Payload;
            """
        )
        data = bytes.fromhex("41 42 43 00")
        result = _decode_struct_entries(data, 0x402000, "Payload", 0, 8, definitions)
        self.assertEqual(result["kind"], "union")
        self.assertEqual(result["fields"][0]["addr"], "0x402000")
        self.assertEqual(result["fields"][1]["addr"], "0x402000")


if __name__ == "__main__":
    unittest.main()
