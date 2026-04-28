import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.vuln_patterns import (
    find_vulnerabilities,
    _check_dangerous_imports,
    _check_dangerous_strings,
    _DANGEROUS,
)


class TestVulnPatterns(unittest.TestCase):

    def test_nonexistent_returns_error(self):
        r = find_vulnerabilities("/nonexistent")
        self.assertIn("error", r)

    def test_result_structure(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 128)
            path = f.name
        try:
            r = find_vulnerabilities(path)
            for field in ("vulnerabilities", "count", "error"):
                self.assertIn(field, r)
        finally:
            os.unlink(path)

    def test_dangerous_dict_nonempty(self):
        self.assertGreater(len(_DANGEROUS), 0)
        self.assertIn("gets", _DANGEROUS)

    def test_gets_detected(self):
        imports = [{"name": "gets"}, {"name": "puts"}]
        vulns = _check_dangerous_imports(imports)
        self.assertTrue(any(v["type"] == "STACK_OVERFLOW" for v in vulns))

    def test_system_detected_as_injection(self):
        imports = [{"name": "system"}]
        vulns = _check_dangerous_imports(imports)
        self.assertTrue(any(v["type"] == "COMMAND_INJECTION" for v in vulns))

    def test_safe_imports_not_flagged(self):
        imports = [{"name": "printf"}, {"name": "malloc"}, {"name": "exit"}]
        vulns = _check_dangerous_imports(imports)
        self.assertEqual(vulns, [])

    def test_vuln_has_required_fields(self):
        imports = [{"name": "gets"}]
        vulns = _check_dangerous_imports(imports)
        for v in vulns:
            for field in ("type", "severity", "description", "cwe"):
                self.assertIn(field, v)

    def test_sprintf_detected(self):
        imports = [{"name": "sprintf"}]
        vulns = _check_dangerous_imports(imports)
        self.assertGreater(len(vulns), 0)

    def test_isoc23_scanf_detected_as_stack_overflow(self):
        imports = [{"name": "__isoc23_scanf@GLIBC_2.38"}]
        vulns = _check_dangerous_imports(imports)

        self.assertTrue(any(v["function"] == "__isoc23_scanf@GLIBC_2.38" for v in vulns))
        self.assertTrue(any(v["type"] == "STACK_OVERFLOW" for v in vulns))

    def test_severity_values_valid(self):
        imports = [{"name": "gets"}, {"name": "system"}, {"name": "strcpy"}]
        vulns = _check_dangerous_imports(imports)
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for v in vulns:
            self.assertIn(v["severity"], valid)

    def test_count_matches_vulnerabilities(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 64)
            path = f.name
        try:
            r = find_vulnerabilities(path)
            self.assertEqual(r["count"], len(r["vulnerabilities"]))
        finally:
            os.unlink(path)

    def test_dangerous_string_fallback_detects_raw_blob_symbols(self):
        vulns = _check_dangerous_strings(b"\x00helper\x00_strcpy\x00safe\x00")

        self.assertTrue(any(v["function"] == "_strcpy" for v in vulns))
        self.assertTrue(all(v.get("source") == "string-reference" for v in vulns))

    def test_find_vulnerabilities_raw_blob_uses_string_fallback(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fRAW\x00system\x00")
            path = f.name
        try:
            result = find_vulnerabilities(path)
            self.assertIsNone(result["error"])
            self.assertEqual(result["count"], 1)
            self.assertEqual(result["vulnerabilities"][0]["function"], "system")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
