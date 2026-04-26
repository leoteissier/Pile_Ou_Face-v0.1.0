"""Détection de packers (UPX, ASPack, MPRESS, Themida…) dans les binaires.

Méthodes :
  1. Signatures bytes (UPX, ASPack, MPRESS, PECompact, FSG, Themida, Enigma, MEW)
  2. Heuristique entropie : section .text > 7.2 bits/byte → probable chiffrement/pack
  3. Anomalies PE headers : SizeOfRawData >> VirtualSize → données compressées
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Signatures bytes : (nom, bytes)
_BYTE_SIGNATURES: list[tuple[str, bytes]] = [
    ("UPX", b"UPX!"),
    ("UPX", b"UPX0"),
    ("UPX", b"UPX1"),
    ("UPX", b"UPX2"),
    ("ASPack", b"ASPack"),
    ("ASPack", b"aPLib"),
    ("MPRESS", b"MPRESS1"),
    ("MPRESS", b"MPRESS2"),
    ("PECompact", b"PECompact2"),
    ("PECompact", b"\x9a\x02\x00\x00"),  # magic PECompact
    ("FSG", b"FSG!"),
    ("Themida", b"Themida"),
    ("Themida", b".winlice"),
    ("Enigma", b"Enigma protector"),
    ("MEW", b"MEW "),
    ("NsPack", b"NsPack"),
    ("PESpin", b"PESpin"),
    ("Obsidium", b"Obsidium"),
]

# Seuil entropie pour flag "section suspecte"
_ENTROPY_THRESHOLD = 7.2

# Ratio SizeOfRawData / VirtualSize au-delà duquel c'est suspect (PE uniquement)
_PE_RAW_VS_VIRT_RATIO = 1.5


def detect_packers(binary_path: str) -> dict:
    """Détecte les packers dans un binaire (signatures + heuristiques).

    Returns:
        {
            "packers": [{"name": str, "confidence": str, "offsets": [...], "reason": str}],
            "score": int,   // 0-100
            "raw": [str],
            "error": null
        }
    """
    result: dict[str, Any] = {"packers": [], "score": 0, "raw": [], "error": None}
    try:
        data = Path(binary_path).read_bytes()
    except OSError as e:
        result["error"] = str(e)
        return result

    found: dict[str, dict] = {}  # nom → entrée packer

    # 1. Signatures bytes
    for name, sig in _BYTE_SIGNATURES:
        offsets = _find_all(data, sig)
        if offsets:
            entry = found.setdefault(
                name,
                {
                    "name": name,
                    "confidence": "high",
                    "offsets": [],
                    "reason": "signature",
                },
            )
            entry["offsets"].extend(
                {"signature": sig.decode("latin-1", errors="replace"), "offset": hex(o)}
                for o in offsets
            )
            entry["offsets"] = entry["offsets"][:20]
            if name not in [r.split()[0] for r in result["raw"]]:
                result["raw"].append(
                    f"{name} détecté ({len(offsets)} occurrence(s) de signature)"
                )

    # 2. Heuristique entropie (via entropy module si disponible, sinon inline)
    _check_entropy_heuristic(binary_path, data, found, result)

    # 3. Anomalies PE headers
    _check_pe_anomalies(data, found, result)

    result["packers"] = list(found.values())
    result["score"] = min(100, len(found) * 40 + len(result["raw"]) * 5)
    return result


def _find_all(data: bytes, needle: bytes) -> list[int]:
    """Trouve toutes les occurrences de needle dans data."""
    offsets = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def _check_entropy_heuristic(
    binary_path: str, data: bytes, found: dict, result: dict
) -> None:
    """Vérifie l'entropie des sections (ou globale si aucune section parseable)."""
    from backends.static.entropy import _entropy_by_section, entropy_of_bytes

    flagged = False
    try:
        sections = _entropy_by_section(binary_path, data)
        for sec in sections:
            if sec["entropy"] >= _ENTROPY_THRESHOLD and sec["size"] > 512:
                flagged = True
                entry = found.setdefault(
                    "HighEntropy",
                    {
                        "name": "HighEntropy",
                        "confidence": "medium",
                        "offsets": [],
                        "reason": "high_entropy",
                    },
                )
                entry["offsets"].append(
                    {
                        "section": sec["name"],
                        "entropy": sec["entropy"],
                        "offset": sec["offset_hex"],
                    }
                )
                msg = f"Section {sec['name']} : entropie {sec['entropy']:.2f} ≥ {_ENTROPY_THRESHOLD} (packed/encrypted)"
                if msg not in result["raw"]:
                    result["raw"].append(msg)
    except Exception:
        pass

    # Fallback global si aucune section analysée
    if not flagged and len(data) > 512:
        e = entropy_of_bytes(data)
        if e >= _ENTROPY_THRESHOLD:
            found.setdefault(
                "HighEntropy",
                {
                    "name": "HighEntropy",
                    "confidence": "low",
                    "offsets": [],
                    "reason": "high_entropy_global",
                },
            )
            result["raw"].append(f"Entropie globale élevée : {e:.2f} bits/byte")


def _check_pe_anomalies(data: bytes, found: dict, result: dict) -> None:
    """Détecte les anomalies de headers PE (SizeOfRawData vs VirtualSize)."""
    if len(data) < 64 or data[:2] != b"MZ":
        return
    try:
        import struct

        e_lfanew = struct.unpack_from("<I", data, 60)[0]
        if e_lfanew + 24 > len(data):
            return
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sect_table_offset = e_lfanew + 24 + opt_size
        anomalies = []
        for i in range(num_sections):
            sh = sect_table_offset + i * 40
            if sh + 40 > len(data):
                break
            name = data[sh : sh + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
            virt_size = struct.unpack_from("<I", data, sh + 16)[0]
            raw_size = struct.unpack_from("<I", data, sh + 20)[0]
            if virt_size > 0 and raw_size > 0:
                ratio = raw_size / virt_size
                if ratio > _PE_RAW_VS_VIRT_RATIO:
                    anomalies.append(
                        f"Section {name!r}: SizeOfRawData ({raw_size}) >> VirtualSize ({virt_size})"
                    )
        if anomalies:
            entry = found.setdefault(
                "PEAnomalies",
                {
                    "name": "PEAnomalies",
                    "confidence": "medium",
                    "offsets": [],
                    "reason": "pe_header_anomaly",
                },
            )
            for msg in anomalies:
                if msg not in result["raw"]:
                    result["raw"].append(msg)
                entry["offsets"].append({"anomaly": msg})
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Détecte les packers (UPX) dans un binaire"
    )
    parser.add_argument("--binary", required=True, help="Chemin du binaire")
    parser.add_argument("--json", action="store_true", help="Sortie JSON")
    args = parser.parse_args()

    out = detect_packers(args.binary)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        if out.get("error"):
            print(f"Erreur: {out['error']}", file=sys.stderr)
            return 1
        if not out["packers"]:
            print("Aucun packer détecté.")
        else:
            for p in out["packers"]:
                print(
                    f"{p['name']} ({p['confidence']}): {len(p['offsets'])} signature(s)"
                )
                for o in p["offsets"][:5]:
                    print(f"  - {o['signature']} @ {o['offset']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
