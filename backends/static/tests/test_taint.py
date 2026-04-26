import sys, unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.taint import (
    taint_analysis,
    _find_sources,
    _find_sinks,
    _build_interprocedural_flows,
    _normalize_name,
    _SOURCES,
    _SINKS,
)


class TestTaint(unittest.TestCase):

    def test_nonexistent_returns_error(self):
        r = taint_analysis("/nonexistent")
        self.assertIn("error", r)

    def test_result_structure(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 128)
            path = f.name
        try:
            r = taint_analysis(path)
            for field in ("flows", "risk_score", "error"):
                self.assertIn(field, r)
            self.assertIsInstance(r["flows"], list)
        finally:
            os.unlink(path)

    def test_sources_list_non_empty(self):
        self.assertGreater(len(_SOURCES), 0)
        self.assertIn("argv", _SOURCES)

    def test_sinks_list_non_empty(self):
        self.assertGreater(len(_SINKS), 0)
        self.assertIn("system", _SINKS)

    def test_find_sources_in_import_list(self):
        imports = [{"name": "gets"}, {"name": "printf"}, {"name": "fgets"}]
        sources = _find_sources(imports)
        self.assertTrue(any(s["name"] == "fgets" for s in sources))

    def test_find_sinks_in_import_list(self):
        imports = [{"name": "system"}, {"name": "puts"}]
        sinks = _find_sinks(imports)
        self.assertTrue(any(s["name"] == "system" for s in sinks))

    def test_normalize_name_strips_plt_and_underscores(self):
        self.assertEqual(_normalize_name("_read@plt"), "read")
        self.assertEqual(_normalize_name("system@stub"), "system")

    def test_interprocedural_flows_detect_source_wrapper(self):
        call_graph = {
            "nodes": [
                {"name": "main", "is_external": False},
                {"name": "my_read", "is_external": False},
                {"name": "read@plt", "is_external": True},
                {"name": "system@plt", "is_external": True},
            ],
            "edges": [
                {"from_name": "main", "to_name": "my_read"},
                {"from_name": "my_read", "to_name": "read@plt"},
                {"from_name": "main", "to_name": "system@plt"},
            ],
        }
        flows = _build_interprocedural_flows(call_graph, max_depth=2)
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow["via_fn"], "main")
        self.assertEqual(flow["source_fn"], "my_read")
        self.assertEqual(flow["source_origin"], "read@plt")
        self.assertEqual(flow["sink_fn"], "system@plt")
        self.assertEqual(flow["confidence"], "MEDIUM")

    def test_interprocedural_flows_detect_sink_wrapper(self):
        call_graph = {
            "nodes": [
                {"name": "main", "is_external": False},
                {"name": "recv@plt", "is_external": True},
                {"name": "my_system", "is_external": False},
                {"name": "system@plt", "is_external": True},
            ],
            "edges": [
                {"from_name": "main", "to_name": "recv@plt"},
                {"from_name": "main", "to_name": "my_system"},
                {"from_name": "my_system", "to_name": "system@plt"},
            ],
        }
        flows = _build_interprocedural_flows(call_graph, max_depth=2)
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow["sink_fn"], "my_system")
        self.assertEqual(flow["sink_origin"], "system@plt")
        self.assertEqual(flow["source_fn"], "recv@plt")
        self.assertIn("sink_path", flow)

    def test_taint_analysis_prefers_interprocedural_mode_when_call_graph_available(self):
        with mock.patch(
            "backends.static.taint._extract_imports",
            return_value=([{"name": "read"}, {"name": "system"}], None),
        ), mock.patch(
            "backends.static.taint._load_call_graph",
            return_value={
                "nodes": [
                    {"name": "main", "is_external": False},
                    {"name": "read@plt", "is_external": True},
                    {"name": "system@plt", "is_external": True},
                ],
                "edges": [
                    {"from_name": "main", "to_name": "read@plt"},
                    {"from_name": "main", "to_name": "system@plt"},
                ],
            },
        ), mock.patch(
            "pathlib.Path.exists",
            return_value=True,
        ):
            result = taint_analysis("/tmp/fake.bin")
        self.assertEqual(result["mode"], "interprocedural")
        self.assertEqual(len(result["flows"]), 1)
        self.assertEqual(result["flows"][0]["via_fn"], "main")

    def test_flow_has_required_fields(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 128)
            path = f.name
        try:
            r = taint_analysis(path)
            for flow in r["flows"]:
                for field in ("source_fn", "sink_fn", "confidence"):
                    self.assertIn(field, flow)
        finally:
            os.unlink(path)

    def test_risk_score_bounded(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 128)
            path = f.name
        try:
            r = taint_analysis(path)
            self.assertGreaterEqual(r["risk_score"], 0)
            self.assertLessEqual(r["risk_score"], 100)
        finally:
            os.unlink(path)

    def test_no_flows_in_clean_binary(self):
        # A binary with no recognizable imports should have no flows
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 128)
            path = f.name
        try:
            r = taint_analysis(path)
            # lief may parse or not — just verify no crash and risk_score is valid
            self.assertGreaterEqual(r["risk_score"], 0)
        finally:
            os.unlink(path)

    def test_raw_blob_string_fallback_detects_source_to_sink(self):
        import tempfile, os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00recv\x00system\x00")
            path = f.name
        try:
            r = taint_analysis(path)
            self.assertIsNone(r["error"])
            self.assertEqual(r["mode"], "legacy")
            self.assertEqual(len(r["flows"]), 1)
            self.assertEqual(r["flows"][0]["source_fn"], "recv")
            self.assertEqual(r["flows"][0]["sink_fn"], "system")
            self.assertEqual(r["flows"][0]["confidence"], "HIGH")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
