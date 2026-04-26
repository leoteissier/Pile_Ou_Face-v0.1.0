# backends/static/tests/test_structs.py
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.structs import (
    compute_struct_layout,
    load_struct_store,
    parse_struct_definitions,
    save_struct_source,
)


class TestStructs(unittest.TestCase):

    def test_parse_typedef_struct_with_array(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Demo {
              uint32_t magic;
              char name[8];
              uint16_t flags;
            } Demo;
            """
        )
        self.assertIn("Demo", definitions)
        self.assertEqual(len(definitions["Demo"]["fields"]), 3)
        self.assertEqual(definitions["Demo"]["fields"][1]["array_len"], 8)

    def test_compute_layout_with_padding(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Demo {
              uint8_t tag;
              uint32_t value;
            } Demo;
            """
        )
        layout = compute_struct_layout(definitions, "Demo", 8)
        self.assertEqual(layout["fields"][0]["offset"], 0)
        self.assertEqual(layout["fields"][1]["offset"], 4)
        self.assertEqual(layout["size"], 8)

    def test_save_and_load_struct_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source(
                """
                typedef struct Header {
                  uint32_t magic;
                  uint16_t count;
                } Header;
                """,
                workspace_root=tmp,
            )
            store = load_struct_store(tmp)
            self.assertIn("Header", store["definitions"])
            self.assertIn("typedef struct Header", store["source"])

    def test_parse_enum_and_union_definitions(self):
        definitions = parse_struct_definitions(
            """
            typedef enum Mode {
              MODE_NONE,
              MODE_READ = 1 << 0,
              MODE_WRITE = 1 << 1,
              MODE_RW = MODE_READ | MODE_WRITE
            } Mode;

            typedef union Payload {
              uint32_t raw;
              char text[4];
            } Payload;
            """
        )
        self.assertEqual(definitions["Mode"]["kind"], "enum")
        self.assertEqual(definitions["Mode"]["value_map"]["MODE_RW"], 3)
        self.assertEqual(definitions["Payload"]["kind"], "union")
        self.assertEqual(len(definitions["Payload"]["fields"]), 2)

    def test_compute_layout_with_nested_union_and_enum_alias(self):
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
        union_layout = compute_struct_layout(definitions, "Payload", 8)
        self.assertEqual(union_layout["kind"], "union")
        self.assertEqual(union_layout["size"], 4)
        self.assertTrue(all(field["offset"] == 0 for field in union_layout["fields"]))

        packet_layout = compute_struct_layout(definitions, "Packet", 8)
        self.assertEqual(packet_layout["fields"][0]["offset"], 0)
        self.assertEqual(packet_layout["fields"][0]["type_kind"], "enum")
        self.assertEqual(packet_layout["fields"][1]["offset"], 4)
        self.assertEqual(packet_layout["fields"][1]["type_kind"], "union")
        self.assertEqual(packet_layout["size"], 8)


if __name__ == "__main__":
    unittest.main()
