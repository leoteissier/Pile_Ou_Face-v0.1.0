"""Scan YARA : applique des règles YARA sur un binaire."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from backends.shared.log import configure_logging, get_logger

logger = get_logger(__name__)


def _yara_available() -> bool:
    """Vérifie si la CLI yara est installée."""
    return shutil.which("yara") is not None


def scan_with_yara(
    binary_path: str,
    rules_path: str | None = None,
    timeout: int = 60,
    project_root: str | None = None,
    global_config_path: str | None = None,
) -> tuple[list[dict], str | None]:
    """Applique des règles YARA sur un binaire via la CLI `yara`.

    rules_path: chemin vers un .yar ou dossier (optionnel si project_root fourni)
    project_root: racine du projet pour les règles custom (.pile-ou-face/rules/yara/)
    """
    path = Path(binary_path)
    if not path.exists():
        return [], "Binaire introuvable."

    extra = Path(rules_path) if rules_path else None
    if extra is not None and not extra.exists():
        return [], "Fichier ou dossier de règles introuvable."

    if project_root:
        from backends.static.rules_manager import RulesManager

        mgr = RulesManager(project_root, global_config_path)
        all_paths = mgr.get_active_yara_paths(extra_path=extra)
    else:
        all_paths = [extra] if extra else []

    if not all_paths:
        return [], (
            "Aucune règle YARA définie. "
            "Ajoutez des règles via l'interface ou passez --rules."
        )

    if not _yara_available():
        return [], (
            "YARA n'est pas installé. Sur macOS : brew install yara. "
            "Sur Linux : sudo apt install yara."
        )

    rules_args: list[str] = []
    for p in all_paths:
        if p.is_dir():
            yar_files = sorted(p.glob("*.yar")) + sorted(p.glob("*.yara"))
            rules_args.extend(str(f) for f in yar_files)
        else:
            rules_args.append(str(p))

    if not rules_args:
        return [], "Aucun fichier .yar trouvé dans les dossiers de règles."

    try:
        result = subprocess.run(
            ["yara", "-s"] + rules_args + [str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        err = str(e) if e else "YARA a échoué."
        if isinstance(e, FileNotFoundError):
            err = "YARA CLI introuvable. Sur macOS : brew install yara."
        return [], err

    if result.returncode not in (0, 1):
        stderr = (result.stderr or "").strip()
        return [], stderr or f"YARA a échoué (code {result.returncode})."

    output = result.stdout or ""
    matches = _parse_yara_output(output, path)
    return matches, None


def _parse_yara_output(output: str, binary_path: Path) -> list[dict[str, object]]:
    """Parse la sortie de yara -s.
    Format YARA 4.x:
      - "RuleName path" (ligne de match)
      - "offset:identifier: hex" (lignes de strings, optionnel avec -s)
    """
    try:
        data = binary_path.read_bytes()
    except OSError:
        return []

    rule_matches: dict[str, list[dict]] = {}
    current_rule = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue

        first = parts[0]
        # Ligne "offset:identifier: hex..." : premier token = 0x...:...
        if first.startswith("0x") and ":" in first and current_rule:
            off_str = first.split(":")[0]
            try:
                offset = int(off_str.replace("0x", ""), 16)
            except ValueError:
                continue
            matched = ""
            if offset < len(data):
                chunk = data[offset : min(offset + 32, len(data))]
                matched = chunk.hex()
            if current_rule not in rule_matches:
                rule_matches[current_rule] = []
            rule_matches[current_rule].append(
                {
                    "offset": offset,
                    "offset_hex": f"0x{offset:x}",
                    "matched": matched,
                }
            )
        else:
            # Ligne "RuleName path" : header de règle
            if current_rule and current_rule not in rule_matches:
                rule_matches[current_rule] = []
            current_rule = first

    if current_rule and current_rule not in rule_matches:
        rule_matches[current_rule] = []

    return [{"rule": r, "matches": m, "tags": []} for r, m in rule_matches.items()]


def main() -> int:
    """Point d'entrée CLI : exécute YARA sur un binaire.
    Output JSON: {"matches": [...], "error": null} ou {"matches": [], "error": "..."}
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Run YARA rules on binary")
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument(
        "--rules", help="Path to .yar file or rules directory (optional)"
    )
    parser.add_argument("--cwd", help="Project root for custom rules (.pile-ou-face/)")
    parser.add_argument(
        "--global-config", dest="global_config", help="Global rules-config.json"
    )
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds")
    args = parser.parse_args()

    configure_logging()

    results, error = scan_with_yara(
        args.binary,
        rules_path=args.rules,
        timeout=args.timeout,
        project_root=args.cwd,
        global_config_path=args.global_config,
    )
    payload = {"matches": results, "error": error}
    out = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        if error:
            logger.warning("YARA error: %s", error)
        else:
            print(
                f"YARA matches written to {args.output} ({len(results)} rule(s) matched)"
            )
    else:
        print(out)
    return 0 if error is None else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
