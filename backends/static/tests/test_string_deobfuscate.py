import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.string_deobfuscate import (
    deobfuscate_strings,
    _extract_hardcoded_key_candidates,
    _rc4_crypt,
    _scan_asm_stackstrings,
    _scan_xor_windows,
    _try_xor_single,
    _try_rot,
    _is_printable_string,
)


class TestStringDeobfuscate(unittest.TestCase):

    def test_nonexistent_returns_empty(self):
        r = deobfuscate_strings("/nonexistent")
        self.assertEqual(r, [])

    def test_xor_single_byte(self):
        plain = b"hello world"
        xored = bytes(b ^ 0x42 for b in plain)
        result = _try_xor_single(xored)
        self.assertIsNotNone(result)
        decoded, key = result
        self.assertEqual(decoded, "hello world")
        self.assertEqual(key, 0x42)

    def test_xor_no_match_random(self):
        import os

        data = os.urandom(20)
        _try_xor_single(data)  # no assertion, just no crash

    def test_xor_windows_split_adjacent_regions(self):
        left = bytes(b ^ 0xFF for b in b"hello world")
        right = bytes(b ^ 0xFE for b in b"test flag")
        hits = _scan_xor_windows(
            left + right,
            base_offset=0x20,
            offset_map={0x20: 0x4020, 0x2B: 0x402B},
        )
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["decoded"], "hello world")
        self.assertEqual(hits[0]["addr"], "0x4020")
        self.assertEqual(hits[1]["decoded"], "test flag")
        self.assertEqual(hits[1]["addr"], "0x402b")

    def test_deobfuscate_strings_recovers_adjacent_xor_strings(self):
        import tempfile

        blob = (bytes(b ^ 0xFF for b in b"hello world")
                + bytes(b ^ 0xFE for b in b"test flag"))
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob)
            path = f.name
        try:
            results = deobfuscate_strings(path)
        finally:
            Path(path).unlink(missing_ok=True)

        decoded = {item["decoded"] for item in results}
        self.assertIn("hello world", decoded)
        self.assertIn("test flag", decoded)

    def test_scan_asm_stackstrings_x86_direct_writes(self):
        asm = """
            mov byte ptr [rbp-0x4], 0x74
            mov byte ptr [rbp-0x3], 0x65
            mov byte ptr [rbp-0x2], 0x73
            mov byte ptr [rbp-0x1], 0x74
        """
        hits = _scan_asm_stackstrings(asm)
        self.assertTrue(any(item["decoded"] == "test" for item in hits))

    def test_scan_asm_stackstrings_riscv_mips_style(self):
        asm = """
            li a0, 0x66
            sb a0, 0(sp)
            addi a0, zero, 0x6c
            sb a0, 1(sp)
            li a0, 0x61
            sb a0, 2(sp)
            li a0, 0x67
            sb a0, 3(sp)
        """
        hits = _scan_asm_stackstrings(asm)
        self.assertTrue(any(item["decoded"] == "flag" for item in hits))

    def test_deobfuscate_strings_reads_asm_stackstrings(self):
        import tempfile

        asm = """
            movz w8, #0x6f
            strb w8, [sp, #0]
            movz w8, #0x70
            strb w8, [sp, #1]
            movz w8, #0x65
            strb w8, [sp, #2]
            movz w8, #0x6e
            strb w8, [sp, #3]
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix=".asm") as f:
            f.write(asm.encode())
            path = f.name
        try:
            results = deobfuscate_strings(path)
        finally:
            Path(path).unlink(missing_ok=True)

        self.assertTrue(any(item["decoded"] == "open" for item in results))

    def test_rot13(self):
        import codecs

        plain = "hello"
        rotated = codecs.encode(plain, "rot_13").encode()
        result = _try_rot(rotated)
        self.assertIsNotNone(result)
        decoded, n = result
        self.assertEqual(decoded, "hello")

    def test_is_printable_string_true(self):
        self.assertTrue(_is_printable_string("hello world"))

    def test_is_printable_string_false_short(self):
        self.assertFalse(_is_printable_string("hi"))  # < 4 chars

    def test_is_printable_string_false_nonprintable(self):
        self.assertFalse(_is_printable_string("\x00\x01\x02\x03\x04"))

    def test_extract_hardcoded_key_candidates_keeps_ascii_and_hex_keys(self):
        data = b"noise secretKey42\x00 00112233445566778899aabbccddeeff tail"
        candidates = _extract_hardcoded_key_candidates(data)
        keys = {entry["key"] for entry in candidates}
        self.assertIn(b"secretKey42", keys)
        self.assertIn(bytes.fromhex("00112233445566778899aabbccddeeff"), keys)

    def test_deobfuscate_strings_recovers_rc4_with_hardcoded_key(self):
        import tempfile

        key = b"secretKey42"
        plain = b"hello world from rc4"
        blob = b"prefix:" + key + b"\x00" + _rc4_crypt(key, plain) + b":suffix"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob)
            path = f.name
        try:
            results = deobfuscate_strings(path)
        finally:
            Path(path).unlink(missing_ok=True)

        rc4_hits = [item for item in results if item.get("method") == "RC4"]
        self.assertTrue(any(item["decoded"] == plain.decode() for item in rc4_hits))
        self.assertTrue(any(item.get("key_hint") == "secretKey42" for item in rc4_hits))

    @unittest.skipUnless("cryptography" in sys.modules or __import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
    def test_deobfuscate_strings_recovers_aes_ecb_with_hardcoded_key(self):
        import tempfile
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = b"0123456789abcdef"
        plain = b"hello aes world!"
        pad_len = 16 - (len(plain) % 16)
        padded = plain + bytes([pad_len]) * pad_len
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        blob = b"hdr:" + key + b"\x00" + encrypted + b":ftr"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob)
            path = f.name
        try:
            results = deobfuscate_strings(path)
        finally:
            Path(path).unlink(missing_ok=True)

        aes_hits = [item for item in results if item.get("method") == "AES-ECB"]
        self.assertTrue(any(item["decoded"] == plain.decode() for item in aes_hits))


if __name__ == "__main__":
    unittest.main()
