# @category POF
# Script angr standalone — appelé directement par Python.
# Usage: python angr_decompile.py --binary <path> [--addr 0x1234] [--full]
# Nécessite: pip install angr
#
# Sortie JSON : liste de {addr, name, code, error?}
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _find_func_by_addr(project, addr: int):
    """Retourne la CFGFast + la fonction à l'adresse donnée."""
    cfg = project.analyses.CFGFast(normalize=True, show_progressbar=False)
    kb = project.kb
    try:
        func = kb.functions.get_by_addr(addr)
        return cfg, func
    except KeyError:
        return cfg, None


def _decompile_function(project, func) -> str:
    """Lance le décompilateur intégré angr (angr.analyses.Decompiler)."""
    try:
        dec = project.analyses.Decompiler(func, cfg=None)
        if dec.codegen:
            return dec.codegen.text
        return ""
    except Exception as exc:
        return f"/* angr decompiler error: {exc} */"


def decompile(binary_path: str, target_addr: str = "", full: bool = False) -> list:
    """Décompile via angr. Retourne une liste de {addr, name, code}."""
    try:
        import angr  # noqa: PLC0415
    except ImportError:
        return [{"error": "angr non installé — pip install angr"}]

    try:
        # load_options: headless, pas de librairies système
        project = angr.Project(
            binary_path,
            auto_load_libs=False,
            load_debug_info=False,
        )
    except Exception as exc:
        return [{"error": f"angr load error: {exc}"}]

    results: list[dict] = []

    if target_addr:
        # Mode fonction unique
        try:
            addr_int = int(target_addr, 16) if target_addr.startswith("0x") else int(target_addr, 10)
        except ValueError:
            return [{"error": f"Adresse invalide : {target_addr}"}]

        try:
            cfg = project.analyses.CFGFast(normalize=True, show_progressbar=False)
            func = project.kb.functions.get_by_addr(addr_int)
        except (KeyError, Exception) as exc:
            return [{"error": f"Fonction introuvable à {target_addr}: {exc}"}]

        code = _decompile_function(project, func)
        results.append({
            "addr": target_addr,
            "name": func.name or f"sub_{addr_int:x}",
            "code": code,
        })

    elif full:
        # Mode binaire complet
        try:
            cfg = project.analyses.CFGFast(normalize=True, show_progressbar=False)
        except Exception as exc:
            return [{"error": f"CFGFast error: {exc}"}]

        for addr_int, func in project.kb.functions.items():
            # Ignorer les PLT / stubs importés
            if func.is_plt or func.is_simprocedure:
                continue
            code = _decompile_function(project, func)
            if not code.strip():
                continue
            results.append({
                "addr": f"0x{addr_int:x}",
                "name": func.name or f"sub_{addr_int:x}",
                "code": code,
            })

    else:
        return [{"error": "Fournir --addr ou --full"}]

    return results if results else [{"error": "Aucune fonction décompilée"}]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Décompile via angr")
    parser.add_argument("--binary", required=True, help="Chemin vers le binaire")
    parser.add_argument("--addr", default="", help="Adresse hex de la fonction (ex: 0x401000)")
    parser.add_argument("--full", action="store_true", help="Décompiler tout le binaire")
    args = parser.parse_args()

    try:
        r = decompile(args.binary, args.addr, args.full)
        print(json.dumps(r, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps([{"error": str(exc)}]))
        sys.exit(1)
