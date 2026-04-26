"""Analyse comportementale statique : réseau, crypto, persistence, évasion.

CLI:
  python behavior.py --binary <path>

Output JSON:
  {
    "indicators": [{"category", "evidence", "severity", "addr"}],
    "score": int,
    "error": null
  }
"""

from __future__ import annotations
import argparse, json, re
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger

_log = get_logger(__name__)

_SEVERITY_SCORES = {"LOW": 5, "MEDIUM": 15, "HIGH": 25, "CRITICAL": 40}

_IP_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_URL_RE = re.compile(rb"https?://[^\s\x00]{4,80}")

_AES_SBOX_PREFIX = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5])

_VM_STRINGS = [
    b"vmware",
    b"virtualbox",
    b"vbox",
    b"qemu",
    b"sandbox",
    b"cuckoo",
    b"wireshark",
]
_PERSISTENCE_PATTERNS = [
    b"HKEY_CURRENT_USER",
    b"CurrentVersion\\Run",
    b"HKEY_LOCAL_MACHINE",
    b"/etc/cron",
    b"/etc/rc.",
    b"systemd",
    b"launchd",
]
_EXFIL_KEYWORDS = [b"upload", b"exfil", b"beacon", b"C2", b"c2_server"]


def _find_network_indicators(data: bytes) -> list[dict]:
    found = []
    for m in _IP_RE.finditer(data):
        ip = m.group().decode()
        if not ip.startswith(("127.", "0.0.0.", "255.")):
            found.append(
                {
                    "category": "NETWORK",
                    "evidence": f"IP: {ip}",
                    "severity": "MEDIUM",
                    "offset": m.start(),
                }
            )
    for m in _URL_RE.finditer(data):
        found.append(
            {
                "category": "NETWORK",
                "evidence": f'URL: {m.group().decode(errors="replace")[:60]}',
                "severity": "HIGH",
                "offset": m.start(),
            }
        )
    return found


def _find_crypto_constants(data: bytes) -> list[dict]:
    found = []
    if _AES_SBOX_PREFIX in data:
        idx = data.index(_AES_SBOX_PREFIX)
        found.append(
            {
                "category": "CRYPTO",
                "evidence": f"AES S-box constant at offset {hex(idx)}",
                "severity": "MEDIUM",
                "offset": idx,
            }
        )
    return found


def _find_evasion_indicators(data: bytes) -> list[dict]:
    found = []
    lower = data.lower()
    for vm in _VM_STRINGS:
        if vm in lower:
            idx = lower.index(vm)
            found.append(
                {
                    "category": "EVASION",
                    "evidence": f"VM string: {vm.decode()}",
                    "severity": "MEDIUM",
                    "offset": idx,
                }
            )
    return found


def _find_persistence_indicators(data: bytes) -> list[dict]:
    found = []
    for pat in _PERSISTENCE_PATTERNS:
        if pat in data:
            idx = data.index(pat)
            found.append(
                {
                    "category": "PERSISTENCE",
                    "evidence": pat.decode(errors="replace"),
                    "severity": "HIGH",
                    "offset": idx,
                }
            )
    return found


def _find_exfiltration_indicators(
    data: bytes, network: list, crypto: list
) -> list[dict]:
    if not network or not crypto:
        return []
    lower = data.lower()
    for kw in _EXFIL_KEYWORDS:
        if kw.lower() in lower:
            return [
                {
                    "category": "EXFILTRATION",
                    "evidence": f"Keyword + network + crypto: {kw.decode()}",
                    "severity": "CRITICAL",
                    "offset": 0,
                }
            ]
    return []


def _compute_score(indicators: list[dict]) -> int:
    total = sum(_SEVERITY_SCORES.get(i.get("severity", "LOW"), 5) for i in indicators)
    return min(100, total)


def analyze_behavior(binary_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {"indicators": [], "score": 0, "error": None}
    try:
        data = Path(binary_path).read_bytes()
    except Exception as e:
        _log.warning("Cannot read binary %s: %s", binary_path, e)
        result["error"] = str(e)
        return result
    net = _find_network_indicators(data)
    crypto = _find_crypto_constants(data)
    evasion = _find_evasion_indicators(data)
    persistence = _find_persistence_indicators(data)
    exfil = _find_exfiltration_indicators(data, net, crypto)
    all_indicators = net + crypto + evasion + persistence + exfil
    result["indicators"] = all_indicators
    result["score"] = _compute_score(all_indicators)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(analyze_behavior(args.binary), indent=2))
