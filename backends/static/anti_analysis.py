"""Détection de techniques anti-analyse (anti-debug, VM detection, timing checks).

CLI:
  python anti_analysis.py --binary <path>

Output JSON: [{technique, description, bypass, confidence, addr?}]
"""

from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger

_log = get_logger(__name__)

_VM_STRINGS = [
    (b"vmware", "VM string: VMware détecté", "Patch la comparaison de string"),
    (b"virtualbox", "VM string: VirtualBox détecté", "Patch la comparaison de string"),
    (b"vbox", "VM string: VBox détecté", "Patch la comparaison de string"),
    (b"qemu", "VM string: QEMU détecté", "Patch la comparaison de string"),
    (b"sandbox", "VM string: Sandbox détecté", "Patch la comparaison de string"),
    (b"cuckoo", "VM string: Cuckoo détecté", "Patch la comparaison de string"),
    (b"wireshark", "VM string: Wireshark détecté", "Fermer Wireshark ou patch"),
]

_RDTSC = b"\x0f\x31"
_CPUID = b"\x0f\xa2"
_ANTI_DEBUG_IMPORTS = [
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "zwqueryinformationprocess",
    "outputdebugstringa",
    "outputdebugstringw",
]


def _check_vm_strings(data: bytes) -> list[dict[str, Any]]:
    lower = data.lower()
    results = []
    for pattern, desc, bypass in _VM_STRINGS:
        if pattern in lower:
            idx = lower.index(pattern)
            results.append(
                {
                    "technique": "VM_DETECTION",
                    "description": desc,
                    "bypass": bypass,
                    "confidence": "HIGH",
                    "addr": hex(idx),
                }
            )
    return results


def _check_timing(data: bytes) -> list[dict[str, Any]]:
    results = []
    i = 0
    while i < len(data) - 1:
        if data[i : i + 2] == _RDTSC:
            window = data[i + 2 : i + 12]
            if _CPUID in window or _RDTSC in window:
                results.append(
                    {
                        "technique": "TIMING_CHECK",
                        "description": "Séquence RDTSC+CPUID (mesure de timing anti-debug)",
                        "bypass": "Patch RDTSC → MOV eax, 0 / xor eax, eax",
                        "confidence": "MEDIUM",
                        "addr": hex(i),
                    }
                )
                i += 10
                continue
        i += 1
    return results


def _check_anti_debug_imports(binary_path: str) -> list[dict[str, Any]]:
    results = []
    try:
        import lief

        binary = lief.parse(binary_path)
        if binary is None:
            return results
        imports = []
        if hasattr(binary, "imported_functions"):
            imports = [str(f) for f in binary.imported_functions]
        elif hasattr(binary, "imports"):
            for lib in binary.imports:
                for e in lib.entries:
                    imports.append(e.name or "")
        for fn in imports:
            if fn.lower() in _ANTI_DEBUG_IMPORTS:
                results.append(
                    {
                        "technique": "ANTI_DEBUG_IMPORT",
                        "description": f"Import anti-debug : {fn}",
                        "bypass": f"Hook ou patch {fn} pour retourner 0",
                        "confidence": "HIGH",
                        "addr": "?",
                    }
                )
    except Exception as e:
        _log.debug("lief error in anti_debug check: %s", e)
    return results


def detect_anti_analysis(binary_path: str) -> list[dict[str, Any]]:
    try:
        data = Path(binary_path).read_bytes()
    except Exception as e:
        _log.warning("Cannot read binary %s: %s", binary_path, e)
        return []
    results = []
    results += _check_vm_strings(data)
    results += _check_timing(data)
    results += _check_anti_debug_imports(binary_path)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(detect_anti_analysis(args.binary), indent=2))
