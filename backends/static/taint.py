"""Analyse de taint simplifiée avec propagation inter-procédurale légère.

CLI:
  python taint.py --binary <path>

Output JSON:
  {
    "flows": [
      {
        "source_fn",
        "sink_fn",
        "confidence",
        "via_fn",
        "source_origin",
        "sink_origin",
        "source_path",
        "sink_path"
      }
    ],
    "risk_score": int,
    "error": null
  }
"""

from __future__ import annotations

import argparse
import json
import re
from collections import deque
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger

_log = get_logger(__name__)

_SOURCES = [
    "argv",
    "envp",
    "read",
    "recv",
    "recvfrom",
    "fgets",
    "scanf",
    "fscanf",
    "getenv",
    "gets",
]
_SINKS = [
    "system",
    "execve",
    "execvp",
    "execl",
    "popen",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "memcpy",
    "printf",
]

_CONFIDENCE = {
    ("gets", "strcpy"): "HIGH",
    ("scanf", "system"): "HIGH",
    ("fgets", "sprintf"): "MEDIUM",
    ("recv", "system"): "HIGH",
    ("getenv", "system"): "HIGH",
}
_CONFIDENCE_WEIGHT = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}


def _normalize_name(name: str) -> str:
    text = str(name or "").strip()
    if not text:
        return ""
    text = text.strip("<>").strip()
    text = text.split("@", 1)[0]
    if "+" in text:
        text = text.split("+", 1)[0]
    return text.lstrip("_").lower()


def _find_sources(imports: list[dict]) -> list[dict]:
    return [
        {"name": i["name"], "addr": i.get("addr", "?")}
        for i in imports
        if _normalize_name(i.get("name", "")) in _SOURCES
    ]


def _find_sinks(imports: list[dict]) -> list[dict]:
    return [
        {"name": i["name"], "addr": i.get("addr", "?")}
        for i in imports
        if _normalize_name(i.get("name", "")) in _SINKS
    ]


def _compute_confidence(source: str, sink: str) -> str:
    return _CONFIDENCE.get((_normalize_name(source), _normalize_name(sink)), "LOW")


def _compute_risk(flows: list[dict]) -> int:
    return min(
        100,
        sum(_CONFIDENCE_WEIGHT.get(f.get("confidence", "LOW"), 5) for f in flows),
    )


def _fallback_import_strings(binary_path: str) -> tuple[list[dict], str | None]:
    try:
        data = Path(binary_path).read_bytes()
    except Exception as exc:
        return [], str(exc)

    wanted = {_normalize_name(name) for name in [*_SOURCES, *_SINKS]}
    imports: list[dict] = []
    seen: set[str] = set()
    for match in re.finditer(rb"[A-Za-z_][A-Za-z0-9_@.$]{1,96}", data):
        raw_name = match.group().decode("ascii", errors="ignore")
        normalized = _normalize_name(raw_name)
        if normalized not in wanted or normalized in seen:
            continue
        seen.add(normalized)
        imports.append(
            {
                "name": raw_name,
                "addr": hex(match.start()),
                "source": "string-reference",
            }
        )
    return imports, None


def _extract_imports(binary_path: str) -> tuple[list[dict], str | None]:
    try:
        import lief

        binary = lief.parse(binary_path)
        if binary is None:
            return _fallback_import_strings(binary_path)
        imports = []
        if hasattr(binary, "imported_functions"):
            for fn in binary.imported_functions:
                imports.append(
                    {"name": fn if isinstance(fn, str) else getattr(fn, "name", "")}
                )
        elif hasattr(binary, "imports"):
            for lib in binary.imports:
                for entry in lib.entries:
                    imports.append({"name": entry.name or ""})
        return imports, None
    except Exception as exc:
        _log.warning("lief parse error for %s: %s", binary_path, exc)
        imports, fallback_error = _fallback_import_strings(binary_path)
        return imports, fallback_error if fallback_error is not None else None


def _with_line_numbers(lines: list[dict]) -> list[dict]:
    result = []
    for idx, line in enumerate(lines, start=1):
        copied = dict(line)
        copied.setdefault("line", idx)
        result.append(copied)
    return result


def _load_call_graph(binary_path: str) -> dict[str, Any]:
    from backends.static.cache import DisasmCache, default_cache_path
    from backends.static.call_graph import build_call_graph
    from backends.static.cfg import build_cfg
    from backends.static.disasm import disassemble_with_capstone
    from backends.static.symbols import extract_symbols

    cache_path = default_cache_path(binary_path)
    with DisasmCache(cache_path) as cache:
        disasm_hit = cache.get_disasm(binary_path)
        if disasm_hit is not None:
            _, lines = disasm_hit
            lines = _with_line_numbers(lines)
        else:
            raw_lines = disassemble_with_capstone(binary_path) or []
            lines = _with_line_numbers(raw_lines)
            if lines:
                cache.save_disasm(binary_path, lines)

        if not lines:
            return {"nodes": [], "edges": []}

        cfg = cache.get_cfg(binary_path)
        if cfg is None:
            cfg = build_cfg(lines, binary_path=binary_path)
            cache.save_cfg(binary_path, cfg)

        symbols = cache.get_symbols(binary_path)
        if symbols is None:
            symbols = extract_symbols(binary_path)
            if symbols:
                cache.save_symbols(binary_path, symbols)

    return build_call_graph(cfg, symbols or [], lines=lines, binary_path=binary_path)


def _build_adjacency(call_graph: dict[str, Any]) -> tuple[dict[str, set[str]], dict[str, dict]]:
    nodes = {
        str(node.get("name") or node.get("addr") or ""): dict(node)
        for node in call_graph.get("nodes", []) or []
        if str(node.get("name") or node.get("addr") or "").strip()
    }
    adjacency: dict[str, set[str]] = {name: set() for name in nodes}
    for edge in call_graph.get("edges", []) or []:
        from_name = str(edge.get("from_name") or edge.get("from") or "").strip()
        to_name = str(edge.get("to_name") or edge.get("to") or "").strip()
        if not from_name or not to_name:
            continue
        adjacency.setdefault(from_name, set()).add(to_name)
        nodes.setdefault(from_name, {"name": from_name, "is_external": False})
        nodes.setdefault(
            to_name,
            {
                "name": to_name,
                "is_external": ("@plt" in to_name or "@stub" in to_name),
            },
        )
    return adjacency, nodes


def _find_reachable_targets(
    start: str,
    adjacency: dict[str, set[str]],
    matcher: Any,
    *,
    max_depth: int = 2,
) -> list[list[str]]:
    queue = deque([(start, [start], 0)])
    best_depth: dict[str, int] = {start: 0}
    matches: list[list[str]] = []
    seen_match_keys: set[tuple[str, ...]] = set()

    while queue:
        node, path, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nxt in sorted(adjacency.get(node, set())):
            next_depth = depth + 1
            if best_depth.get(nxt, 1_000_000) < next_depth:
                continue
            best_depth[nxt] = next_depth
            next_path = path + [nxt]
            if matcher(nxt):
                key = tuple(next_path)
                if key not in seen_match_keys:
                    seen_match_keys.add(key)
                    matches.append(next_path)
                continue
            queue.append((nxt, next_path, next_depth))
    return matches


def _derive_exposed_name(path: list[str]) -> str:
    if len(path) >= 3:
        return path[1]
    return path[-1]


def _compute_path_confidence(
    source_origin: str,
    sink_origin: str,
    source_depth: int,
    sink_depth: int,
    *,
    has_wrapper: bool,
) -> str:
    score = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}[_compute_confidence(source_origin, sink_origin)]
    if source_depth <= 2:
        score += 1
    if sink_depth <= 2:
        score += 1
    if has_wrapper:
        score += 1
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def _build_interprocedural_flows(
    call_graph: dict[str, Any],
    *,
    max_depth: int = 2,
) -> list[dict[str, Any]]:
    adjacency, nodes = _build_adjacency(call_graph)
    if not adjacency:
        return []

    internal_nodes = [
        name
        for name, node in nodes.items()
        if not node.get("is_external") and name
    ]

    flows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for carrier in sorted(internal_nodes):
        source_paths = _find_reachable_targets(
            carrier,
            adjacency,
            lambda name: _normalize_name(name) in _SOURCES,
            max_depth=max_depth,
        )
        sink_paths = _find_reachable_targets(
            carrier,
            adjacency,
            lambda name: _normalize_name(name) in _SINKS,
            max_depth=max_depth,
        )
        if not source_paths or not sink_paths:
            continue

        for source_path in source_paths:
            for sink_path in sink_paths:
                source_origin = source_path[-1]
                sink_origin = sink_path[-1]
                source_fn = _derive_exposed_name(source_path)
                sink_fn = _derive_exposed_name(sink_path)
                key = (carrier, source_fn, sink_fn)
                if key in seen:
                    continue
                seen.add(key)
                has_wrapper = len(source_path) > 2 or len(sink_path) > 2
                flows.append(
                    {
                        "source_fn": source_fn,
                        "sink_fn": sink_fn,
                        "confidence": _compute_path_confidence(
                            source_origin,
                            sink_origin,
                            len(source_path) - 1,
                            len(sink_path) - 1,
                            has_wrapper=has_wrapper,
                        ),
                        "via_fn": carrier,
                        "source_origin": source_origin,
                        "sink_origin": sink_origin,
                        "source_path": source_path,
                        "sink_path": sink_path,
                    }
                )
    return flows


def taint_analysis(binary_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "flows": [],
        "risk_score": 0,
        "error": None,
        "mode": "legacy",
    }
    if not Path(binary_path).exists():
        result["error"] = f"Fichier introuvable : {binary_path}"
        return result

    imports, parse_error = _extract_imports(binary_path)
    sources = _find_sources(imports)
    sinks = _find_sinks(imports)

    call_graph: dict[str, Any] = {"nodes": [], "edges": []}
    try:
        call_graph = _load_call_graph(binary_path)
    except Exception as exc:
        _log.debug("call graph unavailable for %s: %s", binary_path, exc)

    flows = _build_interprocedural_flows(call_graph, max_depth=2)
    if flows:
        result["flows"] = flows
        result["risk_score"] = _compute_risk(flows)
        result["mode"] = "interprocedural"
        return result

    legacy_flows = []
    for src in sources:
        for snk in sinks:
            legacy_flows.append(
                {
                    "source_fn": src["name"],
                    "sink_fn": snk["name"],
                    "confidence": _compute_confidence(src["name"], snk["name"]),
                }
            )
    result["flows"] = legacy_flows
    result["risk_score"] = _compute_risk(legacy_flows)
    result["error"] = parse_error
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(taint_analysis(args.binary), indent=2))
