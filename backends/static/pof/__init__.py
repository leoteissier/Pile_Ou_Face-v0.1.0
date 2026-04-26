"""pof — Pile ou Face scripting API.

Provides Python functions that call the static analysis backends.
Each function runs its backend as a subprocess and returns the parsed JSON dict,
with an added `ok` field (`True` on success, `False` on error).

Usage in scripts:
    from pof import symbols, disasm, decompile
    syms = symbols("/path/to/binary")
    for s in syms.get("symbols", []):
        print(s["name"])
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_VENV_PYTHON = os.path.join(_ROOT, "backends", ".venv", "bin", "python3")
_PYTHON = _VENV_PYTHON if os.path.isfile(_VENV_PYTHON) else sys.executable
_ENV = {**os.environ, "PYTHONPATH": _ROOT}


def _run_backend(script: str, args: list[str], timeout: int = 30) -> dict:
    """Run a backend script and return its parsed JSON output with an `ok` field.

    If the backend returns a JSON list, wraps it as ``{"ok": True, "data": [...]}``
    so callers always receive a dict.
    """
    script_path = os.path.join(_ROOT, "backends", "static", script)
    result = subprocess.run(
        [_PYTHON, script_path, *args],
        capture_output=True, text=True, timeout=timeout, cwd=_ROOT, env=_ENV,
    )
    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            return {"ok": True, "data": data}
        if isinstance(data, dict) and "ok" not in data:
            data["ok"] = True
        return data
    except json.JSONDecodeError:
        return {"ok": False, "error": result.stderr.strip() or "No JSON output"}


def symbols(binary: str) -> dict:
    return _run_backend("symbols.py", ["--binary", binary])


def disasm(binary: str, addr: str | None = None) -> dict:
    args = ["--binary", binary]
    if addr:
        args += ["--addr", addr]
    return _run_backend("disasm.py", args)


def decompile(binary: str, addr: str | None = None, quality: str | None = None) -> dict:
    args = ["--binary", binary]
    if addr:
        args += ["--addr", addr]
    if quality:
        args += ["--quality", quality]
    return _run_backend("decompile.py", args)


def xrefs(binary: str, addr: str) -> dict:
    return _run_backend("xrefs.py", ["--binary", binary, "--addr", addr])


def strings(binary: str) -> dict:
    return _run_backend("strings.py", ["--binary", binary])


def sections(binary: str) -> dict:
    return _run_backend("sections.py", ["--binary", binary])


def info(binary: str) -> dict:
    return _run_backend("headers.py", ["--binary", binary])


def cfg(binary: str, addr: str) -> dict:
    return _run_backend("cfg.py", ["--binary", binary, "--addr", addr])


def rop(binary: str) -> dict:
    return _run_backend("rop_gadgets.py", ["--binary", binary])


def behavior(binary: str) -> dict:
    return _run_backend("behavior.py", ["--binary", binary])


def taint(binary: str) -> dict:
    return _run_backend("taint.py", ["--binary", binary])


def vulns(binary: str) -> dict:
    return _run_backend("vuln_patterns.py", ["--binary", binary])


def flirt(binary: str) -> dict:
    return _run_backend("flirt.py", ["--binary", binary])


def bindiff(binary_a: str, binary_b: str, threshold: float = 0.60) -> dict:
    return _run_backend("bindiff.py", [
        "--binary-a", binary_a, "--binary-b", binary_b,
        "--threshold", str(threshold),
    ])


def deobfuscate(binary: str) -> dict:
    return _run_backend("string_deobfuscate.py", ["--binary", binary])


def anti_analysis(binary: str) -> dict:
    return _run_backend("anti_analysis.py", ["--binary", binary])


def entropy(binary: str) -> dict:
    return _run_backend("entropy.py", ["--binary", binary])


def packer_detect(binary: str) -> dict:
    return _run_backend("packer_detect.py", ["--binary", binary])


def yara_scan(binary: str, rules: str | None = None) -> dict:
    args = ["--binary", binary]
    if rules:
        args += ["--rules", rules]
    return _run_backend("yara_scan.py", args)


def capa(binary: str, rules: str | None = None) -> dict:
    args = ["--binary", binary]
    if rules:
        args += ["--rules", rules]
    return _run_backend("capa_scan.py", args)


def hex_view(binary: str, offset: int = 0, length: int = 256) -> dict:
    return _run_backend("hex_view.py", [
        "--binary", binary,
        "--offset", str(offset),
        "--length", str(length),
    ])


def stack_frame(binary: str, addr: str) -> dict:
    return _run_backend("stack_frame.py", ["--binary", binary, "--addr", addr])


def analysis_index(binary: str, cache_db: str | None = None, force: bool = False) -> dict:
    args = ["--binary", binary]
    if cache_db:
        args += ["--cache-db", cache_db]
    if force:
        args.append("--force")
    return _run_backend("analysis_index.py", args)


def call_graph(mapping_json: str, binary: str | None = None) -> dict:
    """Construit le call graph depuis un mapping JSON de désassemblage.

    Args:
        mapping_json: Chemin vers le fichier JSON produit par disasm.py.
        binary: Chemin optionnel du binaire (pour la résolution des symboles PLT).
    """
    args = ["--mapping", mapping_json]
    if binary:
        args += ["--binary", binary]
    return _run_backend("call_graph.py", args)


def discover_functions(mapping_json: str, binary: str | None = None) -> dict:
    """Découvre les fonctions non référencées par heuristiques de prologue.

    Args:
        mapping_json: Chemin vers le fichier JSON produit par disasm.py.
        binary: Chemin optionnel du binaire (pour symboles connus + FLIRT).
    """
    args = ["--mapping", mapping_json]
    if binary:
        args += ["--binary", binary]
    return _run_backend("discover_functions.py", args)
