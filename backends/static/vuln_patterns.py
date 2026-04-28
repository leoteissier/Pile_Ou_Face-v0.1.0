"""Détection de patterns de vulnérabilités (stack overflow, command injection…).

CLI:
  python vuln_patterns.py --binary <path>

Output JSON:
  {"vulnerabilities": [{type, severity, description, cwe, addr, function}], "count": int, "error": null}
"""

from __future__ import annotations
import argparse, json, re
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger

_log = get_logger(__name__)

_DANGEROUS: dict[str, tuple[str, str, str, str]] = {
    "gets": ("STACK_OVERFLOW", "HIGH", "gets() sans limite de taille", "CWE-121"),
    "strcpy": (
        "STACK_OVERFLOW",
        "HIGH",
        "strcpy() sans vérification de taille",
        "CWE-121",
    ),
    "strcat": (
        "STACK_OVERFLOW",
        "HIGH",
        "strcat() sans vérification de taille",
        "CWE-121",
    ),
    "sprintf": ("STACK_OVERFLOW", "HIGH", "sprintf() sans taille limite", "CWE-121"),
    "vsprintf": ("STACK_OVERFLOW", "HIGH", "vsprintf() sans taille limite", "CWE-121"),
    "scanf": ("STACK_OVERFLOW", "MEDIUM", "scanf %s sans largeur", "CWE-121"),
    "system": (
        "COMMAND_INJECTION",
        "CRITICAL",
        "system() avec argument potentiellement contrôlé",
        "CWE-78",
    ),
    "popen": (
        "COMMAND_INJECTION",
        "CRITICAL",
        "popen() avec argument potentiellement contrôlé",
        "CWE-78",
    ),
    "execve": (
        "COMMAND_INJECTION",
        "CRITICAL",
        "execve() avec argument potentiellement contrôlé",
        "CWE-78",
    ),
    "execl": (
        "COMMAND_INJECTION",
        "CRITICAL",
        "execl() avec argument potentiellement contrôlé",
        "CWE-78",
    ),
}


def _normalize_import_name(raw: str) -> str:
    """Normalize glibc/Mach-O/Windows import name to its canonical form for matching."""
    name = raw.lower()
    # Strip version suffix: gets@@GLIBC_2.2.5 or puts@GLIBC_2.2.5 -> base name
    name = re.sub(r"@@?[^@]+$", "", name)
    # ISO libc variants: __isoc99_scanf / __isoc23_scanf -> scanf.
    # This must run before single-_ strip so the double-underscore prefix is kept intact.
    for prefix in ("__isoc99_", "__isoc23_"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    # Fortified versions (__strcpy_chk) are safe — skip matching
    if name.endswith("_chk"):
        return ""
    # Mach-O convention: _strcpy -> strcpy (strip exactly one leading underscore)
    if name.startswith("_") and not name.startswith("__"):
        name = name[1:]
    # Windows A/W suffix (single char): MessageBoxA -> MessageBox
    if len(name) > 2 and name[-1] in ("a", "w") and name[:-1] in _DANGEROUS:
        name = name[:-1]
    return name


def _check_dangerous_imports(imports: list[dict]) -> list[dict[str, Any]]:
    found = []
    seen: set[str] = set()
    for imp in imports:
        name = _normalize_import_name(imp.get("name", ""))
        if name and name in _DANGEROUS and name not in seen:
            seen.add(name)
            vtype, severity, desc, cwe = _DANGEROUS[name]
            found.append(
                {
                    "type": vtype,
                    "severity": severity,
                    "description": desc,
                    "cwe": cwe,
                    "addr": imp.get("addr", "?"),
                    "function": imp.get("name", name),
                }
            )
    return found


def _check_dangerous_strings(data: bytes) -> list[dict[str, Any]]:
    """Fallback when import tables are unavailable.

    Many raw blobs, relocatable objects, firmware chunks, or uncommon ISAs do
    not expose imports through LIEF. Symbol/string references still give a
    useful cross-architecture signal, so we scan printable tokens and report
    matches with a lower-confidence source.
    """
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    pattern = rb"[A-Za-z_][A-Za-z0-9_@.$]{1,96}"
    for match in re.finditer(pattern, data):
        raw_name = match.group().decode("ascii", errors="ignore")
        name = _normalize_import_name(raw_name)
        if name and name in _DANGEROUS and name not in seen:
            seen.add(name)
            vtype, severity, desc, cwe = _DANGEROUS[name]
            found.append(
                {
                    "type": vtype,
                    "severity": severity,
                    "description": desc,
                    "cwe": cwe,
                    "addr": hex(match.start()),
                    "function": raw_name,
                    "source": "string-reference",
                }
            )
    return found


def _fallback_scan_file(binary_path: str, result: dict[str, Any]) -> dict[str, Any]:
    try:
        data = Path(binary_path).read_bytes()
    except Exception as e:
        result["error"] = str(e)
        return result
    vulns = _check_dangerous_strings(data)
    result["vulnerabilities"] = vulns
    result["count"] = len(vulns)
    result["error"] = None
    return result


def find_vulnerabilities(binary_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {"vulnerabilities": [], "count": 0, "error": None}
    if not Path(binary_path).exists():
        result["error"] = f"Fichier introuvable : {binary_path}"
        return result
    try:
        import lief

        binary = lief.parse(binary_path)
        if binary is None:
            return _fallback_scan_file(binary_path, result)
        imports = []
        if hasattr(binary, "imported_functions"):
            for fn in binary.imported_functions:
                imports.append(
                    {"name": fn if isinstance(fn, str) else getattr(fn, "name", "")}
                )
        elif hasattr(binary, "imports"):
            for lib in binary.imports:
                for entry in lib.entries:
                    imports.append(
                        {
                            "name": entry.name or "",
                            "addr": (
                                hex(entry.iat_address)
                                if hasattr(entry, "iat_address")
                                else "?"
                            ),
                        }
                    )
        vulns = _check_dangerous_imports(imports)
        result["vulnerabilities"] = vulns
        result["count"] = len(vulns)
    except Exception as e:
        _log.warning("Error analyzing %s: %s", binary_path, e)
        return _fallback_scan_file(binary_path, result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(find_vulnerabilities(args.binary), indent=2))
