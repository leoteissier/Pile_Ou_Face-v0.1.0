"""FLIRT-like signature matching pour identifier des fonctions connues (libc, OpenSSL...).

CLI:
  python flirt.py --binary <path>

Output JSON: [{addr, name, lib, confidence}]
"""

from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger

_log = get_logger(__name__)
_SIGS_PATH = Path(__file__).parent / "data" / "flirt_sigs.json"


def _load_sigs() -> list[dict]:
    try:
        return json.loads(_SIGS_PATH.read_text())
    except Exception as e:
        _log.warning("Failed to load flirt_sigs.json: %s", e)
        return []


def _parse_pattern(pattern_str: str) -> list[int | None]:
    """Convertit "55 48 ?? E5" -> [0x55, 0x48, None, 0xE5]"""
    result = []
    for token in pattern_str.split():
        result.append(None if token == "??" else int(token, 16))
    return result


def _match_pattern(data: bytes, offset: int, pattern: list[int | None]) -> bool:
    if offset + len(pattern) > len(data):
        return False
    for i, p in enumerate(pattern):
        if p is not None and data[offset + i] != p:
            return False
    return True


def _build_index(
    compiled: list[tuple[dict, list[int | None]]]
) -> dict[int, list[tuple[dict, list[int | None]]]]:
    """Indexe les signatures par leur premier byte concret.

    Les signatures dont le premier token est '??' (None) tombent dans le
    bucket -1 et sont testées à chaque position (cas rare).
    Réduit le nombre de comparaisons d'un facteur ~nb_buckets.
    """
    index: dict[int, list[tuple[dict, list[int | None]]]] = {}
    for sig, pattern in compiled:
        first = pattern[0] if pattern else None
        key = first if first is not None else -1
        index.setdefault(key, []).append((sig, pattern))
    return index


def match_signatures(binary_path: str) -> list[dict[str, Any]]:
    """Scanne le binaire et retourne les fonctions connues identifiees.

    Utilise un index par premier byte pour éviter O(n × m) : seules les
    signatures dont le premier byte concret correspond à data[i] sont testées.
    """
    try:
        data = Path(binary_path).read_bytes()
    except Exception as e:
        _log.warning("Cannot read binary %s: %s", binary_path, e)
        return []
    sigs = _load_sigs()
    compiled = [(s, _parse_pattern(s["pattern"])) for s in sigs]
    index = _build_index(compiled)
    wildcard_sigs = index.get(-1, [])

    matches = []
    for i, byte in enumerate(data):
        candidates = index.get(byte, []) + wildcard_sigs
        for sig, pattern in candidates:
            if _match_pattern(data, i, pattern):
                addr = hex(i + sig.get("offset", 0))
                matches.append(
                    {
                        "addr": addr,
                        "name": sig["name"],
                        "lib": sig["lib"],
                        "confidence": "medium",
                    }
                )
    return matches


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(match_signatures(args.binary), indent=2))
