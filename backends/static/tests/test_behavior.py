import sys, unittest, tempfile, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.behavior import (
    analyze_behavior,
    _find_network_indicators,
    _find_crypto_constants,
)


class TestBehavior(unittest.TestCase):

    def test_nonexistent_returns_error(self):
        r = analyze_behavior("/nonexistent")
        self.assertIn("error", r)

    def test_result_structure(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 256)
            path = f.name
        try:
            r = analyze_behavior(path)
            for field in ("indicators", "score", "error"):
                self.assertIn(field, r)
            self.assertIsInstance(r["indicators"], list)
            self.assertIsInstance(r["score"], int)
        finally:
            os.unlink(path)

    def test_network_ip_detection(self):
        data = b"connect to 192.168.1.1 for C2"
        indicators = _find_network_indicators(data)
        self.assertTrue(
            any("192.168.1.1" in str(i.get("evidence", "")) for i in indicators)
        )

    def test_network_url_detection(self):
        data = b"http://evil.example.com/payload"
        indicators = _find_network_indicators(data)
        self.assertGreater(len(indicators), 0)

    def test_no_network_in_clean_binary(self):
        data = bytes(range(256))
        indicators = _find_network_indicators(data)
        self.assertEqual(indicators, [])

    def test_aes_constant_detection(self):
        aes_sbox = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01])
        indicators = _find_crypto_constants(aes_sbox)
        self.assertTrue(any("AES" in i.get("evidence", "") for i in indicators))

    def test_score_bounded(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"http://evil.com " + bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2] * 5))
            path = f.name
        try:
            r = analyze_behavior(path)
            self.assertGreaterEqual(r["score"], 0)
            self.assertLessEqual(r["score"], 100)
        finally:
            os.unlink(path)

    def test_indicator_has_required_fields(self):
        data = b"http://evil.example.com/c2"
        indicators = _find_network_indicators(data)
        for ind in indicators:
            for field in ("category", "evidence", "severity"):
                self.assertIn(field, ind)

    def test_vm_string_detection(self):
        import backends.static.behavior as b

        data = b"checking for vmware presence"
        indicators = b._find_evasion_indicators(data)
        self.assertTrue(
            any("vmware" in str(i.get("evidence", "")).lower() for i in indicators)
        )

    def test_persistence_detection(self):
        import backends.static.behavior as b

        data = b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        indicators = b._find_persistence_indicators(data)
        self.assertGreater(len(indicators), 0)


if __name__ == "__main__":
    unittest.main()
