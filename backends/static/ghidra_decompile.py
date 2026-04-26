# @category POF
# Module PyGhidra — importé directement dans decompile.py (pas via subprocess).
# Compatible PyGhidra 3.x (API GhidraProject + pyghidra.analyze).
#
# Stratégie pour les binaires sans fonctions :
#   1. importProgram + _analyze_program (standard analyze=True de pyghidra)
#   2. pyghidra.analyze(program) → reAnalyzeAll() forcé si 0 fonction après étape 1
#   3. CreateFunctionCmd dans une transaction à l'adresse cible
#   4. FlatProgramAPI.createFunction en dernier recours

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers : installation et localisation
# ---------------------------------------------------------------------------

def _find_ghidra_install_dir() -> str:
    for env_var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        v = os.environ.get(env_var, "").strip()
        if v and Path(v).exists():
            return v
    if Path("/opt/ghidra").exists():
        return "/opt/ghidra"
    keg = Path("/opt/homebrew/opt/ghidra/libexec")
    if keg.exists():
        return str(keg)
    cask_base = Path("/opt/homebrew/Caskroom/ghidra")
    if cask_base.exists():
        for vd in sorted(cask_base.iterdir(), reverse=True):
            for sub in vd.iterdir():
                if (sub / "Ghidra").exists():
                    return str(sub)
    return ""


def _ensure_pyghidra(install_dir: str) -> bool:
    try:
        import pyghidra  # noqa: F401
        return True
    except ImportError:
        pass
    for wheel_dir in [
        Path(install_dir) / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "dist",
        Path(install_dir) / "Features" / "PyGhidra" / "pypkg" / "dist",
    ]:
        wheels = sorted(wheel_dir.glob("pyghidra-*.whl")) if wheel_dir.exists() else []
        if wheels:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", str(wheels[-1]), "--quiet"],
                capture_output=True,
            )
            if r.returncode == 0:
                return True
    return False


# ---------------------------------------------------------------------------
# Helpers : analyse Ghidra
# ---------------------------------------------------------------------------

def _do_standard_analysis(flat_api, program):
    """Passe d'analyse standard (identique à analyze=True dans open_program)."""
    try:
        from ghidra.program.util import GhidraProgramUtilities  # type: ignore
        from ghidra.app.script import GhidraScriptUtil  # type: ignore
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            flat_api.analyzeAll(program)
            GhidraProgramUtilities.markProgramAnalyzed(program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
    except Exception:
        pass


def _do_force_reanalyze(program, monitor):
    """Force reAnalyzeAll via AutoAnalysisManager — couvre les cas où analyze=True ne crée rien."""
    try:
        import pyghidra
        pyghidra.analyze(program, monitor)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers : création de fonctions
# ---------------------------------------------------------------------------

def _normalize_symbol_name(name: str) -> str:
    s = str(name or "").strip()
    for pfx in ("sym.imp.", "sym.", "fun.", "sub_", "fcn."):
        if s.startswith(pfx):
            s = s[len(pfx):]
            break
    if s.startswith("_") and len(s) > 1:
        s = s[1:]
    return s.lower()


def _to_ghidra_addr(program, hex_str: str, offset: int):
    af = program.getAddressFactory()
    for candidate in ([hex_str] if hex_str else []) + ([hex(offset), str(offset)] if offset else []):
        if not candidate:
            continue
        try:
            a = af.getAddress(candidate)
            if a is not None:
                return a
        except Exception:
            continue
    return None


def _create_function_at(program, addr, name: str, monitor):
    """Crée une fonction à addr en utilisant CreateFunctionCmd dans une transaction."""
    if addr is None:
        return None
    fm = program.getFunctionManager()

    # Déjà là ?
    func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if func:
        return func

    try:
        import pyghidra
        from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore
        from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore

        with pyghidra.transaction(program, "POF disassemble"):
            cmd = DisassembleCommand(addr, None, True)
            cmd.applyTo(program, monitor)

        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if func:
            return func

        with pyghidra.transaction(program, "POF createFunction"):
            cmd = CreateFunctionCmd(addr, True)
            cmd.applyTo(program, monitor)

        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if func:
            return func
    except Exception:
        pass

    # Dernier recours : FlatProgramAPI
    try:
        import pyghidra
        from ghidra.program.flatapi import FlatProgramAPI  # type: ignore
        flat = FlatProgramAPI(program)
        try:
            with pyghidra.transaction(program, "POF flat disassemble"):
                flat.disassemble(addr)
        except Exception:
            pass
        try:
            with pyghidra.transaction(program, "POF flat createFunction"):
                created = flat.createFunction(addr, name or "pof_func")
            if created:
                return created
        except Exception:
            pass
    except Exception:
        pass

    return fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)


def _collect_functions(program, monitor, target_addr: str, target_offset: int, target_name: str) -> list:
    """Retourne la liste de fonctions Ghidra à décompiler, avec stratégies de fallback."""
    fm = program.getFunctionManager()
    selected: list = []
    seen: set[str] = set()

    def _add(func):
        if not func:
            return
        k = str(func.getEntryPoint())
        if k in seen:
            return
        seen.add(k)
        selected.append(func)

    # ── Par adresse ───────────────────────────────────────────────────────
    if target_offset:
        for f in fm.getFunctions(True):
            ep = f.getEntryPoint()
            if ep and ep.getOffset() == target_offset:
                _add(f)
        if selected:
            return selected

        ghidra_addr = _to_ghidra_addr(program, target_addr, target_offset)
        if ghidra_addr:
            _add(fm.getFunctionAt(ghidra_addr))
            _add(fm.getFunctionContaining(ghidra_addr))
        if selected:
            return selected

        # Si 0 fonction détectée, forcer une analyse complète d'abord
        if fm.getFunctionCount() == 0:
            _do_force_reanalyze(program, monitor)
            for f in fm.getFunctions(True):
                ep = f.getEntryPoint()
                if ep and ep.getOffset() == target_offset:
                    _add(f)
            if ghidra_addr:
                _add(fm.getFunctionAt(ghidra_addr))
                _add(fm.getFunctionContaining(ghidra_addr))
        if selected:
            return selected

        # Créer manuellement la fonction à l'adresse
        if ghidra_addr:
            created = _create_function_at(program, ghidra_addr, target_name, monitor)
            _add(created)
        return selected

    # ── Par nom ───────────────────────────────────────────────────────────
    if target_name:
        wanted = _normalize_symbol_name(target_name)
        for f in fm.getFunctions(True):
            if _normalize_symbol_name(str(f.getName())) == wanted:
                _add(f)
        if selected:
            return selected
        # Chercher dans la table de symboles
        try:
            from ghidra.program.model.symbol import SymbolType  # type: ignore
            it = program.getSymbolTable().getSymbols(target_name)
            while it.hasNext():
                sym = it.next()
                if sym.getSymbolType() in (SymbolType.FUNCTION, SymbolType.LABEL):
                    _add(_create_function_at(program, sym.getAddress(), target_name, monitor))
        except Exception:
            pass
        return selected

    # ── Toutes les fonctions ───────────────────────────────────────────────
    all_funcs = list(fm.getFunctions(True))
    if all_funcs:
        return all_funcs

    # 0 fonction → forcer l'analyse complète
    _do_force_reanalyze(program, monitor)
    return list(fm.getFunctions(True))


def _binary_diagnostics(program) -> str:
    parts = []
    try:
        parts.append(f"arch={program.getLanguage().getLanguageID()}")
    except Exception:
        pass
    try:
        parts.append(f"fonctions={program.getFunctionManager().getFunctionCount()}")
    except Exception:
        pass
    try:
        mem = program.getMemory()
        blocks = list(mem.getBlocks())
        exec_n = sum(1 for b in blocks if b.isExecute())
        parts.append(f"sections={len(blocks)}/{exec_n}exec")
    except Exception:
        pass
    return " | ".join(parts) if parts else "diagnostic indisponible"


def _force_arm64_decompiler_path(install_dir: str) -> None:
    """Contourner l'absence de metadata Ghidra pour linux_arm64.

    Ghidra 12 ne référence pas encore correctement le binaire natif `decompile`
    sur Linux ARM64 dans `Application.getOSFile("decompile")`. Le fichier peut
    exister sur disque mais rester introuvable côté Java. Dans ce cas, on force
    le chemin exact via réflexion avant `DecompInterface.openProgram()`.
    """
    try:
        from ghidra.framework import Application, Platform  # type: ignore
    except Exception:
        return

    try:
        current_platform = Platform.CURRENT_PLATFORM
        os_name = str(current_platform.getOperatingSystem())
        arch_name = str(current_platform.getArchitecture())
    except Exception:
        return

    if "LINUX" not in os_name or "ARM_64" not in arch_name:
        return

    try:
        Application.getOSFile("decompile")
        return
    except Exception:
        pass

    decompile_path = Path(install_dir) / "Ghidra" / "Features" / "Decompiler" / "os" / "linux_arm64" / "decompile"
    if not decompile_path.exists():
        return

    try:
        from java.lang import Class  # type: ignore

        cls = Class.forName("ghidra.app.decompiler.DecompileProcessFactory")
        field = cls.getDeclaredField("exepath")
        field.setAccessible(True)
        field.set(None, str(decompile_path))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def decompile(binary_path: str, target_addr: str = "", target_name: str = "") -> list:
    """Décompile via PyGhidra 3.x. Retourne une liste de {addr, name, code, error}."""
    install_dir = _find_ghidra_install_dir()
    if not install_dir:
        return [{"error": "Ghidra non trouvé — définir GHIDRA_INSTALL_DIR"}]
    if not _ensure_pyghidra(install_dir):
        return [{"error": "pyghidra non disponible"}]

    os.environ.setdefault("GHIDRA_INSTALL_DIR", install_dir)

    try:
        import pyghidra
    except ImportError as e:
        return [{"error": f"Import pyghidra échoué : {e}"}]

    # Démarrer la JVM si pas encore démarrée
    if not pyghidra.started():
        try:
            pyghidra.start(install_dir=Path(install_dir))
        except Exception as e:
            return [{"error": f"Démarrage PyGhidra/JVM échoué : {e}"}]

    target_offset = int(target_addr, 16) if target_addr else 0

    try:
        from ghidra.base.project import GhidraProject  # type: ignore
        from ghidra.app.decompiler import DecompInterface  # type: ignore
        from ghidra.program.flatapi import FlatProgramAPI  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        _force_arm64_decompiler_path(install_dir)

        # ConsoleTaskMonitor > DUMMY : supporte cancel check + progress sans bloquer
        try:
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
            monitor = ConsoleTaskMonitor()
        except Exception:
            monitor = TaskMonitor.DUMMY

        with tempfile.TemporaryDirectory(prefix="pof_ghidra_") as tmp_dir:
            project_dir = Path(tmp_dir) / "proj"
            project_dir.mkdir(mode=0o755)

            gp = None
            program = None
            try:
                # Créer le projet Ghidra temporaire (overwrite=True pour éviter les conflits)
                gp = GhidraProject.createProject(str(project_dir), "pof", True)
                program = gp.importProgram(Path(binary_path))
                if program is None:
                    return [{"error": f"Ghidra ne peut pas importer ce binaire : {binary_path}"}]

                # Ouvrir le programme en lecture/écriture (requis pour analyse + décompilation)
                program.setEventsEnabled(False)

                # Analyse standard (équivalent analyze=True)
                flat_api = FlatProgramAPI(program)
                _do_standard_analysis(flat_api, program)
                program.setEventsEnabled(True)

                # Collecter les fonctions (avec fallback reAnalyzeAll + createFunction)
                target_functions = _collect_functions(
                    program, monitor, target_addr, target_offset, target_name
                )

                if not target_functions:
                    diag = _binary_diagnostics(program)
                    addr_hint = f" à {target_addr}" if target_addr else ""
                    return [{
                        "error": (
                            f"Ghidra n'a trouvé aucune fonction décompilable{addr_hint}. "
                            f"Binaire peut-être stripped ou architecture non supportée. "
                            f"Essaie retdec ou angr. Diagnostic : {diag}"
                        )
                    }]

                # Décompiler
                ifc = DecompInterface()
                # DecompileOptions initialisé depuis le programme (hérite arch + langage)
                try:
                    from ghidra.app.decompiler import DecompileOptions  # type: ignore
                    opts = DecompileOptions()
                    opts.grabFromProgram(program)
                    ifc.setOptions(opts)
                except Exception:
                    pass
                # openProgram() peut retourner False/None selon la version de PyGhidra —
                # on l'appelle sans checker le retour ; une exception signale un vrai échec
                try:
                    ifc.openProgram(program)
                except Exception as e:
                    return [{"error": f"DecompInterface.openProgram() exception : {e}"}]

                results = []
                for func in target_functions:
                    entry = func.getEntryPoint()
                    addr_str = f"0x{entry.getOffset():x}"
                    fname = str(func.getName())
                    try:
                        res = ifc.decompileFunction(func, 120, monitor)
                    except Exception as exc:
                        results.append({"addr": addr_str, "name": fname,
                                        "code": "", "error": str(exc)})
                        continue

                    if res is None:
                        results.append({"addr": addr_str, "name": fname,
                                        "code": "", "error": "decompileFunction a retourné None"})
                        continue

                    if res.decompileCompleted():
                        decompiled = res.getDecompiledFunction()
                        c_code = str(decompiled.getC()) if decompiled else ""
                        results.append({"addr": addr_str, "name": fname, "code": c_code})
                    else:
                        # Récupérer le vrai message d'erreur Ghidra
                        err_msg = ""
                        try:
                            err_msg = str(res.getErrorMessage() or "")
                        except Exception:
                            pass
                        print(f"[POF] decompile FAIL {fname}@{addr_str}: {err_msg!r}", file=sys.stderr)
                        # Tentative de fallback : récupérer le C partiel si disponible
                        partial = ""
                        try:
                            df = res.getDecompiledFunction()
                            if df:
                                partial = str(df.getC() or "")
                        except Exception:
                            pass
                        if partial:
                            results.append({"addr": addr_str, "name": fname, "code": partial,
                                            "warning": f"Décompilation partielle{': ' + err_msg if err_msg else ''}"})
                        else:
                            results.append({
                                "addr": addr_str, "name": fname, "code": "",
                                "error": f"Décompilation incomplète{': ' + err_msg if err_msg else ' (pas de message Ghidra)'}",
                            })

                if not results and target_addr:
                    return [{"error": f"Ghidra : aucun résultat pour {target_addr}"}]
                return results

            finally:
                # Ne pas sauvegarder le projet temporaire — évite ReadOnlyException
                try:
                    if gp is not None:
                        gp.close()
                except Exception:
                    pass

    except Exception as e:
        return [{"error": str(e)}]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Décompile via PyGhidra")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--addr", default="")
    parser.add_argument("--func-name", default="")
    args = parser.parse_args()
    try:
        r = decompile(args.binary, args.addr, args.func_name)
        print(json.dumps(r))
    except Exception as e:
        print(json.dumps([{"error": str(e)}]))
