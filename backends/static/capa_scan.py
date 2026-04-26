"""Scan Capa : analyse des capacités d'un binaire (Mandiant capa).

Capa identifie les capacités d'un exécutable (ex: chiffrement, sockets, création de processus,
persistence, exfiltration). Utilisé en analyse malware pour caractériser rapidement un binaire.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

CAPA_RULES_URL = "https://github.com/mandiant/capa-rules"


def _ensure_capa_rules(cwd: str) -> Path | None:
    """Clone capa-rules si absent. Retourne le chemin ou None."""
    target = Path(cwd) / "backends" / "capa-rules"
    if target.exists() and target.is_dir():
        return target
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", CAPA_RULES_URL, str(target)],
            capture_output=True,
            timeout=120,
            check=True,
            cwd=cwd,
        )
        return target if target.exists() else None
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ):
        return None


def _find_capa_rules(
    rules_path: str | None = None, cwd: str | None = None
) -> Path | None:
    """Trouve le dossier capa-rules.
    Ordre: rules_path, CAPA_RULES_PATH, cwd/backends/capa-rules, ~/.capa/rules
    """
    if rules_path:
        p = Path(rules_path)
        if p.exists() and p.is_dir():
            return p
        return None
    env_path = os.environ.get("CAPA_RULES_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists() and p.is_dir():
            return p
    if cwd:
        p = Path(cwd) / "backends" / "capa-rules"
        if p.exists() and p.is_dir():
            return p
        # Auto-clone si absent
        maybe_p = _ensure_capa_rules(cwd)
        if maybe_p:
            return maybe_p
    home = Path.home() / ".capa" / "rules"
    if home.exists() and home.is_dir():
        return home
    return None


def _run_capa_via_api(
    binary_path: str,
    timeout: int,
    rules_path: Path | None = None,
) -> tuple[str, str, int]:
    """Invoque capa via capa.main.main() (évite Permission denied sur l'exécutable)."""
    argv = ["capa", "-j", str(binary_path)]
    if rules_path:
        argv.extend(["-r", str(rules_path)])
    argv_str = json.dumps(argv)
    code = f"import sys; sys.argv={argv_str}; from capa.main import main; main()"
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def _run_capa_via_docker(
    binary_path: str,
    cwd: str,
    timeout: int,
) -> tuple[str, str, int]:
    """Contournement Mac ARM64 : exécute capa dans un conteneur Linux x86_64."""
    try:
        binary = Path(binary_path).resolve()
        cwd_path = Path(cwd).resolve()
        if not str(binary).startswith(str(cwd_path)):
            return "", "binary outside cwd", 1
        rel = binary.relative_to(cwd_path)
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{cwd_path}:/work",
            "-w",
            "/work",
            "python:3.12-slim",
            "bash",
            "-c",
            f"pip install -q flare-capa 2>/dev/null && capa -j /work/{rel} -r /work/backends/capa-rules",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except Exception:
        return "", "docker failed", 1


def scan_with_capa(
    binary_path: str,
    timeout: int = 120,
    rules_path: str | None = None,
    cwd: str | None = None,
    global_config_path: str | None = None,
) -> dict:
    """Exécute capa sur un binaire et retourne les capacités détectées.

    Utilise l'API Python capa.main (évite Permission denied sur l'exécutable pip).
    Nécessite: pip install flare-capa

    rules_path: chemin vers capa-rules (ou CAPA_RULES_PATH, ou cwd/capa-rules, ou ~/.capa/rules)
    cwd: répertoire de travail pour chercher capa-rules/

    Returns:
        {"capabilities": [...], "errors": [...], "meta": {...}} ou {"error": "..."}
    """
    path = Path(binary_path)
    if not path.exists():
        return {"error": "Fichier introuvable", "capabilities": []}

    rules = _find_capa_rules(rules_path, cwd)
    # rules peut être None : flare-capa v7+ embarque ses propres règles,
    # donc on laisse capa tourner sans -r. On bloque uniquement si l'utilisateur
    # a fourni un chemin explicite mais introuvable.
    if rules_path and not rules:
        return {
            "error": f"Capa : règles introuvables dans {rules_path}.",
            "capabilities": [],
        }

    # Injecter les règles CAPA custom actives si présentes
    if cwd and rules:
        try:
            from backends.static.rules_manager import RulesManager

            RulesManager(cwd, global_config_path).inject_active_capa_rules(rules)
        except Exception:
            pass  # Optionnel — le scan continue sans règles custom

    try:
        stdout, stderr, returncode = _run_capa_via_api(str(path), timeout, rules)
    except subprocess.TimeoutExpired:
        return {"error": "capa timeout", "capabilities": []}
    except FileNotFoundError:
        return {
            "error": "capa non installé (pip install flare-capa)",
            "capabilities": [],
        }

    raw = (stdout or "").strip() or (stderr or "").strip()

    # Sur Mac ARM64 : vivisect plante (vivisect.impapi.posix.a64). Contournement Docker.
    # Capa peut afficher "Unexpected exception" sans le détail (sauf en -d), donc on retente aussi sur ModuleNotFoundError.
    retry_docker = (
        cwd
        and rules
        and (
            "vivisect.impapi.posix.a64" in raw
            or "No module named 'vivisect.impapi" in raw
            or ("ModuleNotFoundError" in raw and "Unexpected exception" in raw)
        )
    )
    if retry_docker:
        try:
            stdout, stderr, returncode = _run_capa_via_docker(
                str(path), cwd or os.getcwd(), timeout=min(timeout, 180)
            )
            raw = (stdout or "").strip() or (stderr or "").strip()
        except Exception:
            pass
    if not raw:
        return {"error": "capa a échoué (pas de sortie)", "capabilities": []}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        if "default embedded rules not found" in raw or "E_MISSING_RULES" in raw:
            return {
                "error": "Capa : règles introuvables. Exécutez 'make capa-rules' ou clonez capa-rules.",
                "capabilities": [],
            }
        if (
            "Input file does not appear to be a supported" in raw
            or "supported file" in raw.lower()
        ):
            return {
                "error": "Capa ne supporte que PE (Windows) et ELF (Linux). Sur macOS, gcc produit un Mach-O. "
                "Compilez un ELF pour Linux (ex: make demo dans un conteneur Linux) ou utilisez un binaire Linux.",
                "capabilities": [],
            }
        if (
            "vivisect.impapi.posix.a64" in raw
            or "No module named 'vivisect.impapi" in raw
        ):
            return {
                "error": "Capa : bug vivisect sur macOS ARM64 (Apple Silicon). "
                "Contournement : make capa-docker (ou exécutez capa dans un conteneur Linux x86_64).",
                "capabilities": [],
            }
        if "ModuleNotFoundError" in raw or "Unexpected exception" in raw:
            return {
                "error": "Capa : ModuleNotFoundError (vivisect incompatible sur Mac ARM64). "
                "Contournement : make demo-elf && make capa-docker (Docker requis). "
                "Ou : pip install --upgrade flare-capa si vous êtes sur Linux/x86_64.",
                "capabilities": [],
            }
        # Priorité : ligne ERROR capa:, puis exception (traceback), ignorer "Please report"
        lines = raw.strip().splitlines()
        err_line = None
        for line in lines:
            if "ERROR capa:" in line or "Error:" in line:
                err_line = line.strip()
                break
        if not err_line:
            for line in reversed(lines):
                line = line.strip()
                if (
                    line
                    and "Please also report" not in line
                    and "capa/issues" not in line
                ):
                    if (
                        not line.startswith("File ")
                        and "line " not in line
                        and "Traceback" not in line
                    ):
                        if ":" in line:
                            err_line = line
                            break
        if err_line:
            return {"error": f"Capa : {err_line}", "capabilities": []}
        err_preview = raw[:400] if raw else " (vide)"
        return {"error": f"Capa a échoué : {err_preview}", "capabilities": []}

    capabilities = []
    raw_caps = data.get("capabilities", data.get("rules", []))
    if isinstance(raw_caps, dict):
        raw_caps = [
            {"rule": k, **v} if isinstance(v, dict) else {"rule": k}
            for k, v in raw_caps.items()
        ]
    for cap in raw_caps:
        if isinstance(cap, dict):
            name = cap.get("rule", cap.get("name", "?"))
            matches_str = ""
            if "matches" in cap:
                m = cap["matches"]
                matches_str = str(m)[:80] if m else ""
            elif "locations" in cap:
                locs = cap["locations"]
                matches_str = (
                    ", ".join(str(loc) for loc in locs[:3])[:80] if locs else ""
                )
            capabilities.append(
                {
                    "name": name,
                    "namespace": cap.get("namespace", ""),
                    "locations": cap.get("locations", []),
                    "matches": matches_str,
                }
            )

    return {
        "capabilities": capabilities,
        "errors": data.get("errors", []),
        "meta": data.get("meta", {}),
    }


def main() -> int:
    """Point d'entrée CLI : exécute capa sur un binaire."""
    import argparse

    parser = argparse.ArgumentParser(description="Run capa on binary")
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds")
    parser.add_argument(
        "--rules", help="Path to capa-rules directory (default: auto-detect)"
    )
    parser.add_argument("--cwd", help="Working directory for auto-detecting capa-rules")
    parser.add_argument(
        "--global-config", dest="global_config", help="Global rules-config.json"
    )
    args = parser.parse_args()

    cwd = args.cwd or os.getcwd()
    try:
        result = scan_with_capa(
            args.binary,
            timeout=args.timeout,
            rules_path=getattr(args, "rules", None),
            cwd=cwd,
            global_config_path=getattr(args, "global_config", None),
        )
    except Exception as e:
        result = {"error": str(e), "capabilities": []}
    out = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        caps = result.get("capabilities", [])
        print(f"Capa results written to {args.output} ({len(caps)} capabilities)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
