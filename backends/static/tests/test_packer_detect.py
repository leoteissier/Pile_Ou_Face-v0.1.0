"""Tests pour backends.static.packer_detect."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.packer_detect import detect_packers, _find_all


class TestDetectPackers(unittest.TestCase):

    def _write_tmp(self, data: bytes) -> str:
        import os

        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data)
        f.close()
        self._tmpfiles = getattr(self, "_tmpfiles", [])
        self._tmpfiles.append(f.name)
        return f.name

    def tearDown(self):
        import os

        for p in getattr(self, "_tmpfiles", []):
            try:
                os.unlink(p)
            except OSError:
                pass

    def test_nonexistent_returns_error(self):
        result = detect_packers("/nonexistent/binary")
        self.assertIn("error", result)
        self.assertIsNotNone(result["error"])

    def test_clean_binary_no_packers(self):
        path = self._write_tmp(b"\x7fELF" + b"\x00" * 1024)
        result = detect_packers(path)
        self.assertIsNone(result.get("error"))
        self.assertEqual(result["packers"], [])

    def test_upx_signature_detected(self):
        data = b"\x00" * 64 + b"UPX!" + b"\x00" * 64
        path = self._write_tmp(data)
        result = detect_packers(path)
        names = [p["name"] for p in result["packers"]]
        self.assertIn("UPX", names)
        self.assertEqual(result["score"] > 0, True)

    def test_aspack_signature_detected(self):
        data = b"\x00" * 64 + b"ASPack" + b"\x00" * 64
        path = self._write_tmp(data)
        result = detect_packers(path)
        names = [p["name"] for p in result["packers"]]
        self.assertIn("ASPack", names)

    def test_mpress_signature_detected(self):
        data = b"\x00" * 64 + b"MPRESS1" + b"\x00" * 64
        path = self._write_tmp(data)
        result = detect_packers(path)
        names = [p["name"] for p in result["packers"]]
        self.assertIn("MPRESS", names)

    def test_result_structure(self):
        path = self._write_tmp(b"\x00" * 64)
        result = detect_packers(path)
        for key in ("packers", "score", "raw", "error"):
            self.assertIn(key, result)
        self.assertIsInstance(result["packers"], list)
        self.assertIsInstance(result["score"], int)
        self.assertIsInstance(result["raw"], list)

    def test_score_bounded(self):
        data = b"UPX!" + b"ASPack" + b"MPRESS1" + b"FSG!" + b"Themida" + b"\x00" * 64
        path = self._write_tmp(data)
        result = detect_packers(path)
        self.assertLessEqual(result["score"], 100)

    def test_high_entropy_detected(self):
        """Données aléatoires → entropie élevée → HighEntropy packer détecté."""
        import os

        data = os.urandom(4096)
        path = self._write_tmp(data)
        result = detect_packers(path)
        # Doit au moins signaler l'entropie dans raw ou packers
        all_text = " ".join(result["raw"])
        names = [p["name"] for p in result["packers"]]
        self.assertTrue(
            "HighEntropy" in names or "entropie" in all_text.lower(),
            f"Pas de détection haute entropie. packers={names}, raw={result['raw']}",
        )

    def test_pe_minimal_no_anomaly(self):
        """PE minimal sans anomalie de header."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        import os

        try:
            write_minimal_pe64(pe_path)
            result = detect_packers(pe_path)
            # PE minimal ne doit pas avoir d'anomalie header
            names = [p["name"] for p in result["packers"]]
            self.assertNotIn("PEAnomalies", names)
        finally:
            os.unlink(pe_path)


class TestFindAll(unittest.TestCase):

    def test_no_match(self):
        self.assertEqual(_find_all(b"hello world", b"xyz"), [])

    def test_single_match(self):
        self.assertEqual(_find_all(b"abcde", b"cd"), [2])

    def test_multiple_matches(self):
        self.assertEqual(_find_all(b"aabaa", b"aa"), [0, 3])

    def test_overlapping(self):
        result = _find_all(b"aaa", b"aa")
        self.assertEqual(result, [0, 1])


if __name__ == "__main__":
    unittest.main()
