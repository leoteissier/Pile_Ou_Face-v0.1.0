"""Gestionnaire centralisé des règles YARA et CAPA.

CLI:
  python rules_manager.py list   --cwd <root> [--global-config <path>]
  python rules_manager.py toggle --rule-id <id> --enabled true|false --cwd <root>
  python rules_manager.py add    --name <name> --type yara|capa --content <content> --cwd <root>
  python rules_manager.py delete --rule-id <id> --cwd <root>
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any


class RulesManager:
    """Gère les règles custom YARA et CAPA par projet."""

    _POF_DIR = ".pile-ou-face"

    def __init__(
        self, project_root: str, global_config_path: str | None = None
    ) -> None:
        self._root = Path(project_root)
        self._rules_dir = self._root / self._POF_DIR / "rules"
        self._project_config = self._root / self._POF_DIR / "rules-config.json"
        self._global_config = Path(global_config_path) if global_config_path else None

    def list_rules(self) -> list[dict[str, Any]]:
        """Retourne toutes les règles avec état fusionné global + projet."""
        config = self._merged_config()
        rules: list[dict[str, Any]] = []
        for rule_type, exts in (
            ("yara", ("*.yar", "*.yara")),
            ("capa", ("*.yml", "*.yaml")),
        ):
            d = self._rules_dir / rule_type
            if not d.exists():
                continue
            for ext in exts:
                for f in sorted(d.glob(ext)):
                    rule_id = f"user:{rule_type}:{f.name}"
                    enabled = config.get(rule_id, {}).get("enabled", True)
                    rules.append(
                        {
                            "id": rule_id,
                            "name": f.name,
                            "type": rule_type,
                            "source": "user",
                            "enabled": enabled,
                            "path": str(f),
                        }
                    )
        return rules

    def get_active_yara_paths(self, extra_path: Path | None = None) -> list[Path]:
        """Retourne les chemins des fichiers .yar actifs (enabled)."""
        config = self._merged_config()
        active: list[Path] = []
        d = self._rules_dir / "yara"
        if d.exists():
            for ext in ("*.yar", "*.yara"):
                for f in sorted(d.glob(ext)):
                    rule_id = f"user:yara:{f.name}"
                    if config.get(rule_id, {}).get("enabled", True):
                        active.append(f)
        if extra_path is not None:
            active.append(extra_path)
        return active

    def inject_active_capa_rules(self, capa_rules_path: Path) -> None:
        """Copie les règles CAPA custom actives dans capa_rules_path/custom/."""
        config = self._merged_config()
        d = self._rules_dir / "capa"
        if not d.exists():
            return
        dest = capa_rules_path / "custom"
        dest.mkdir(exist_ok=True)
        for ext in ("*.yml", "*.yaml"):
            for f in sorted(d.glob(ext)):
                rule_id = f"user:capa:{f.name}"
                if config.get(rule_id, {}).get("enabled", True):
                    shutil.copy2(f, dest / f.name)

    def toggle_rule(self, rule_id: str, enabled: bool) -> None:
        """Active ou désactive une règle dans la config projet."""
        cfg = self._load_project_config()
        cfg.setdefault("rules", {})[rule_id] = {"enabled": enabled}
        self._save_project_config(cfg)

    def add_user_rule(self, name: str, content: str, rule_type: str) -> str:
        """Crée un fichier dans .pile-ou-face/rules/{type}/. Retourne rule_id."""
        if rule_type not in ("yara", "capa"):
            raise ValueError(f"Type inconnu : {rule_type!r} (attendu: yara ou capa)")
        d = self._rules_dir / rule_type
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(content, encoding="utf-8")
        return f"user:{rule_type}:{name}"

    def delete_user_rule(self, rule_id: str) -> None:
        """Supprime le fichier et nettoie la config projet."""
        parts = rule_id.split(":", 2)
        if len(parts) != 3 or parts[0] != "user":
            raise ValueError(f"rule_id invalide : {rule_id!r}")
        _, rule_type, name = parts
        f = self._rules_dir / rule_type / name
        if not f.exists():
            raise FileNotFoundError(f"Règle introuvable : {f}")
        f.unlink()
        cfg = self._load_project_config()
        cfg.get("rules", {}).pop(rule_id, None)
        self._save_project_config(cfg)

    def _merged_config(self) -> dict[str, Any]:
        """Merge global (défauts) + projet (overrides)."""
        global_rules: dict[str, Any] = {}
        if self._global_config and self._global_config.exists():
            try:
                global_rules = json.loads(
                    self._global_config.read_text(encoding="utf-8")
                ).get("rules", {})
            except (json.JSONDecodeError, OSError):
                pass
        project_rules = self._load_project_config().get("rules", {})
        return {**global_rules, **project_rules}

    def _load_project_config(self) -> dict[str, Any]:
        if self._project_config.exists():
            try:
                return json.loads(self._project_config.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"version": 1, "rules": {}}

    def _save_project_config(self, config: dict[str, Any]) -> None:
        self._project_config.parent.mkdir(parents=True, exist_ok=True)
        self._project_config.write_text(
            json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def main() -> int:
    """Point d'entrée CLI."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Rules manager for YARA/CAPA")
    sub = parser.add_subparsers(dest="cmd")

    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--cwd", default=os.getcwd())
        p.add_argument("--global-config", dest="global_config")

    p_list = sub.add_parser("list")
    _add_common(p_list)

    p_toggle = sub.add_parser("toggle")
    p_toggle.add_argument("--rule-id", required=True)
    p_toggle.add_argument("--enabled", required=True, choices=("true", "false"))
    _add_common(p_toggle)

    p_add = sub.add_parser("add")
    p_add.add_argument("--name", required=True)
    p_add.add_argument(
        "--type", dest="rule_type", required=True, choices=("yara", "capa")
    )
    p_add.add_argument("--content", required=True)
    _add_common(p_add)

    p_del = sub.add_parser("delete")
    p_del.add_argument("--rule-id", required=True)
    _add_common(p_del)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 1

    mgr = RulesManager(args.cwd, getattr(args, "global_config", None))
    try:
        if args.cmd == "list":
            print(
                json.dumps(
                    {"rules": mgr.list_rules(), "error": None}, ensure_ascii=False
                )
            )
        elif args.cmd == "toggle":
            mgr.toggle_rule(args.rule_id, args.enabled == "true")
            print(json.dumps({"success": True, "error": None}))
        elif args.cmd == "add":
            rule_id = mgr.add_user_rule(args.name, args.content, args.rule_type)
            print(json.dumps({"rule_id": rule_id, "error": None}))
        elif args.cmd == "delete":
            mgr.delete_user_rule(args.rule_id)
            print(json.dumps({"success": True, "error": None}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
