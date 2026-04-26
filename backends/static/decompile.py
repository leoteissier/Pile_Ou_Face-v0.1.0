"""Décompilateur Python via retdec-decompiler.

CLI:
  python decompile.py --binary <path> [--addr 0x401000] [--full]

Output JSON:
  {
    "addr": "0x401000",
    "code": "int f() { ... }",
    "error": null
  }
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger
from backends.static.typed_struct_refs import build_typed_struct_index, typed_struct_signature

_log = get_logger(__name__)
_FILE_SIGNATURE_CACHE: dict[tuple[str, int, int], str] = {}
_DECOMPILE_CACHE_VERSION = "7"
_PLACEHOLDER_SYMBOL_RE = re.compile(
    r"\b(?:local_[0-9a-f]+|var_[0-9a-f]+(?:h)?|param_\d+|arg_[a-z0-9_]+|auStack_[0-9a-f]+|puStack_[0-9a-f]+|"
    r"DAT_[0-9a-f]+|LAB_[0-9a-f]+|PTR_[0-9a-f]+|code_[0-9a-f]+)\b",
    flags=re.IGNORECASE,
)
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TYPE_HINT_RE = re.compile(
    r"\b(?:char|short|int|long|float|double|bool|size_t|ssize_t|"
    r"uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t|struct)\b"
)
_LOW_LEVEL_PSEUDOC_RE = re.compile(
    r"\b(?:loc_0x[0-9a-f]+|sym\.imp\.[A-Za-z_][A-Za-z0-9_]*|"
    r"push|pop|rbp|rsp|ebp|esp|rax|eax|qword|dword|CODE XREF|orphan)\b",
    flags=re.IGNORECASE,
)
_DECOMPILER_QUALITY_BIAS = {
    "ghidra": 5,
    "retdec": 6,
    "angr": 4,
}
_DECOMPILER_PRECISION_BIAS = {
    "ghidra": 0,
    "retdec": 0,
    "angr": 0,
}
_CURATED_BUILTIN_DECOMPILERS = ("ghidra", "retdec", "angr")
_BUILTIN_DECOMPILERS = set(_CURATED_BUILTIN_DECOMPILERS)
_CUSTOM_DECOMPILERS_CONFIG = (
    Path(__file__).resolve().parent.parent.parent / ".pile-ou-face" / "decompilers.json"
)
_DEFAULT_BUILTIN_DOCKER_IMAGES = {
    "ghidra": "pile-ou-face/decompiler-ghidra:latest",
    "angr": "pile-ou-face/decompiler-angr:latest",
    "retdec": "pile-ou-face/decompiler-retdec:latest",
}
_DOCKER_AVAILABLE_CACHE: dict[str, bool] = {}
_PDC_LABEL_RE = re.compile(r"^(?P<indent>\s*)(?P<label>loc_0x[0-9a-f]+):(?:\s*//.*)?$", flags=re.IGNORECASE)
_PDC_GOTO_RE = re.compile(r"^(?P<indent>\s*)goto\s+(?P<label>loc_0x[0-9a-f]+);(?:\s*//.*)?$", flags=re.IGNORECASE)
_PDC_ASSIGN_RE = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+?);?$")


# ---------------------------------------------------------------------------
# Cache disque
# ---------------------------------------------------------------------------


def _file_signature(path: str | None) -> str:
    """Retourne une signature sha256 stable du contenu du fichier."""
    if not path:
        return ""
    try:
        file_path = Path(path)
        stat = file_path.stat()
    except OSError:
        return ""
    cache_key = (str(file_path.resolve()), int(stat.st_mtime_ns), int(stat.st_size))
    cached = _FILE_SIGNATURE_CACHE.get(cache_key)
    if cached:
        return cached
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    signature = digest.hexdigest()
    _FILE_SIGNATURE_CACHE.clear()
    _FILE_SIGNATURE_CACHE[cache_key] = signature
    return signature


def _normalize_quality(quality: str | None) -> str:
    normalized = str(quality or "").strip().lower()
    if normalized in {"max", "precision", "precise", "fidelity"}:
        return "precision"
    return "normal"


def _is_compare_quality(quality: str | None) -> bool:
    return _normalize_quality(quality) == "precision"


def _quality_bias_for_backend(decompiler: str, quality: str) -> int:
    normalized = _normalize_quality(quality)
    if normalized == "precision":
        return _DECOMPILER_PRECISION_BIAS.get(decompiler or "", 0)
    return _DECOMPILER_QUALITY_BIAS.get(decompiler or "", 0)


def _normalize_decompiler_id(value: str | None) -> str:
    """Normalize an external/backend identifier for registry lookups."""
    normalized = re.sub(r"[^a-z0-9_.-]+", "-", str(value or "").strip().lower())
    return normalized.strip("-")


def _load_custom_decompilers(
    config_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Load user-defined decompilers from .pile-ou-face/decompilers.json.

    Expected shape:
      {
        "decompilers": {
          "mytool": {
            "label": "My Decompiler",

            // Exécution locale
            "command": ["mytool", "--json", "--binary", "{binary}", "--addr", "{addr}"],
            "full_command": ["mytool", "--json", "--binary", "{binary}", "--full"],

            // Exécution Docker (prioritaire sur command si provider=docker)
            "docker_image": "registry/mytool:latest",
            "docker_command": ["/usr/bin/mytool", "--json", "--binary", "{binary}", "--addr", "{addr}"],
            "docker_full_command": ["/usr/bin/mytool", "--json", "--binary", "{binary}", "--full"],

            // Options avancées (toutes optionnelles)
            "supports_full": true,
            "timeout": 120,
            "output_format": "json",   // "json" | "c" | "text"  (défaut: "json")
            "network": "none",          // réseau Docker: "none" | "bridge" | "host"
            "env": {"MY_VAR": "val"},   // variables d'environnement injectées
            "docker_extra_args": ["--memory", "2g"]  // args docker run supplémentaires
          }
        }
      }

    Note: Une entrée peut n'avoir que docker_command (sans command locale) — dans ce cas
    elle est uniquement utilisable via provider=docker ou auto quand l'image est dispo.

    Commands are argv arrays on purpose: no implicit shell is used.
    """
    env_path = os.environ.get("POF_DECOMPILERS_CONFIG", "").strip()
    cfg_path = config_path or (Path(env_path) if env_path else _CUSTOM_DECOMPILERS_CONFIG)
    try:
        raw = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    entries = raw.get("decompilers", raw) if isinstance(raw, dict) else {}
    if not isinstance(entries, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for key, value in entries.items():
        decompiler_id = _normalize_decompiler_id(str(key))
        if not decompiler_id or decompiler_id in _BUILTIN_DECOMPILERS:
            continue
        if not isinstance(value, dict):
            continue

        # Commande locale — optionnelle si docker_command présent
        command = value.get("command")
        docker_command = value.get("docker_command")
        has_local = isinstance(command, list) and len(command) > 0
        has_docker = isinstance(docker_command, list) and len(docker_command) > 0
        # Rejeter les entrées sans aucune commande utilisable
        if not has_local and not has_docker:
            _log.debug("Décompilateur custom '%s' ignoré : aucune command ni docker_command", decompiler_id)
            continue

        normalized: dict[str, Any] = {}
        normalized["id"] = decompiler_id
        normalized["label"] = str(value.get("label") or decompiler_id)

        # Commandes locales
        if has_local:
            normalized["command"] = [str(p) for p in command]  # type: ignore[union-attr]
        full_command = value.get("full_command")
        if isinstance(full_command, list) and full_command:
            normalized["full_command"] = [str(p) for p in full_command]

        # Commandes Docker
        if has_docker:
            normalized["docker_command"] = [str(p) for p in docker_command]  # type: ignore[union-attr]
        docker_full = value.get("docker_full_command")
        if isinstance(docker_full, list) and docker_full:
            normalized["docker_full_command"] = [str(p) for p in docker_full]
        docker_image = str(value.get("docker_image") or "").strip()
        if docker_image:
            normalized["docker_image"] = docker_image

        # Options avancées
        normalized["supports_full"] = bool(value.get("supports_full", True))
        raw_timeout = value.get("timeout")
        if raw_timeout is not None:
            try:
                normalized["timeout"] = max(5, int(raw_timeout))
            except (TypeError, ValueError):
                pass

        # Format de sortie : json (défaut), c, text
        output_format = str(value.get("output_format") or "json").strip().lower()
        if output_format not in ("json", "c", "text"):
            output_format = "json"
        normalized["output_format"] = output_format

        # Réseau Docker (par défaut none pour l'isolation)
        network = str(value.get("network") or "none").strip()
        if network not in ("none", "bridge", "host", ""):
            network = "none"
        normalized["network"] = network or "none"

        # Variables d'environnement (dict str→str)
        env_vars = value.get("env") or {}
        if isinstance(env_vars, dict):
            normalized["env"] = {str(k): str(v) for k, v in env_vars.items()}

        # Arguments docker run supplémentaires (liste de str)
        extra_args = value.get("docker_extra_args") or []
        if isinstance(extra_args, list):
            normalized["docker_extra_args"] = [str(a) for a in extra_args]

        result[decompiler_id] = normalized
    return result


def _custom_decompiler_labels() -> dict[str, str]:
    return {
        key: str(value.get("label") or key)
        for key, value in _load_custom_decompilers().items()
    }


def _docker_env_var_name_for_decompiler(decompiler: str) -> str:
    suffix = re.sub(r"[^A-Z0-9]+", "_", _normalize_decompiler_id(decompiler).upper()).strip("_")
    return f"POF_DECOMPILER_IMAGE_{suffix}"


def _get_builtin_docker_image(decompiler: str) -> str:
    normalized = _normalize_decompiler_id(decompiler)
    if normalized not in _BUILTIN_DECOMPILERS:
        return ""
    specific = os.environ.get(_docker_env_var_name_for_decompiler(normalized), "").strip()
    if specific:
        return specific
    legacy = os.environ.get("POF_DECOMPILER_IMAGE", "").strip()
    if legacy:
        return legacy
    return _DEFAULT_BUILTIN_DOCKER_IMAGES.get(normalized, "")


def _get_decompiler_docker_image(decompiler: str) -> str:
    normalized = _normalize_decompiler_id(decompiler)
    custom = _load_custom_decompilers().get(normalized)
    if custom:
        specific = os.environ.get(_docker_env_var_name_for_decompiler(normalized), "").strip()
        if specific:
            return specific
        return str(custom.get("docker_image") or "").strip()
    return _get_builtin_docker_image(normalized)


def _get_all_docker_images() -> dict[str, str]:
    images = {name: _get_builtin_docker_image(name) for name in sorted(_BUILTIN_DECOMPILERS)}
    for name in _load_custom_decompilers():
        image = _get_decompiler_docker_image(name)
        if image:
            images[name] = image
    return {key: value for key, value in images.items() if value}


def _format_custom_command(
    command: list[str],
    *,
    binary_path: str,
    addr: str = "",
    func_name: str = "",
    mode: str = "function",
    out_file: Path | None = None,
) -> list[str]:
    replacements = {
        "binary": binary_path,
        "addr": addr,
        "func_name": func_name,
        "mode": mode,
        "out": str(out_file or ""),
    }
    formatted: list[str] = []
    for part in command:
        text = str(part)
        for key, replacement in replacements.items():
            text = text.replace("{" + key + "}", replacement)
        formatted.append(text)
    return formatted


def _parse_external_decompiler_output(
    stdout: str,
    *,
    decompiler: str,
    addr: str = "",
    out_file: Path | None = None,
    full: bool = False,
    output_format: str = "json",
) -> dict[str, Any]:
    """Parse la sortie d'un décompilateur custom.

    output_format:
      "json"  — JSON dict ou liste (défaut)
      "c"     — code C brut, parsé en blocs de fonctions
      "text"  — texte brut, retourné tel quel dans code
    """
    text = ""
    if out_file and out_file.exists():
        try:
            text = out_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
    if not text:
        text = stdout or ""
    stripped = text.strip()
    if not stripped:
        return {"addr": addr, "code": "", "functions": [], "error": "aucune sortie", "decompiler": decompiler}

    # ── Format C/text : pas de parsing JSON ──────────────────────────────────
    if output_format in ("c", "text"):
        if full:
            blocks = _parse_c_like_function_blocks(stripped) if output_format == "c" else []
            return {
                "functions": blocks,
                "code": stripped,
                "error": None,
                "decompiler": decompiler,
            }
        return {"addr": addr, "code": stripped, "error": None, "decompiler": decompiler}

    # ── Format JSON (défaut) ──────────────────────────────────────────────────
    # Tentative de décodage JSON, avec fallback vers C/text brut
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("decompiler", decompiler)
            if full:
                out.setdefault("functions", [])
            else:
                out.setdefault("addr", addr)
                out.setdefault("code", "")
            out.setdefault("error", None)
            return out
        if isinstance(data, list):
            functions = [
                {
                    "addr": str(item.get("addr") or ""),
                    "name": str(item.get("name") or ""),
                    "code": str(item.get("code") or ""),
                    "error": item.get("error"),
                }
                for item in data
                if isinstance(item, dict)
            ]
            if full:
                return {
                    "functions": [item for item in functions if item.get("code")],
                    "code": "\n\n".join(item["code"] for item in functions if item.get("code")),
                    "error": None,
                    "decompiler": decompiler,
                }
            chosen = next((item for item in functions if item.get("code")), None)
            if chosen:
                return {**chosen, "decompiler": decompiler, "error": chosen.get("error")}
    except Exception:
        pass
    # Fallback : traiter comme C/texte brut
    if full:
        return {
            "functions": _parse_c_like_function_blocks(stripped),
            "code": stripped,
            "error": None,
            "decompiler": decompiler,
        }
    return {"addr": addr, "code": stripped, "error": None, "decompiler": decompiler}


def _run_custom_decompiler(
    decompiler: str,
    binary_path: str,
    *,
    addr: str = "",
    func_name: str = "",
    full: bool = False,
) -> dict[str, Any]:
    config = _load_custom_decompilers().get(_normalize_decompiler_id(decompiler))
    if not config:
        return {"addr": addr, "code": "", "functions": [], "error": f"Décompilateur custom inconnu : {decompiler}", "decompiler": decompiler}
    command = config.get("full_command") if full and config.get("full_command") else config.get("command")
    if full and not config.get("supports_full", True) and not config.get("full_command"):
        return {"functions": [], "error": f"{decompiler} ne déclare pas supports_full", "decompiler": decompiler}
    if not isinstance(command, list) or not command:
        # Mode docker-only : pas de commande locale disponible
        return {"addr": addr, "code": "", "functions": [], "error": f"{decompiler} n'a pas de commande locale (utiliser provider=docker)", "decompiler": decompiler}
    timeout = int(config.get("timeout") or (300 if full else 120))
    # Variables d'environnement : fusionner env courant + vars custom
    proc_env = {**os.environ}
    custom_env = config.get("env") or {}
    if isinstance(custom_env, dict):
        proc_env.update({str(k): str(v) for k, v in custom_env.items()})
    output_format = config.get("output_format", "json")
    try:
        with tempfile.TemporaryDirectory(prefix="pof_custom_decompiler_") as tmp:
            out_ext = ".json" if output_format == "json" else ".c" if output_format == "c" else ".txt"
            out_file = Path(tmp) / f"out{out_ext}"
            argv = _format_custom_command(
                command,
                binary_path=binary_path,
                addr=addr,
                func_name=func_name,
                mode="full" if full else "function",
                out_file=out_file,
            )
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, text=True, env=proc_env)
            parsed = _parse_external_decompiler_output(
                proc.stdout,
                decompiler=decompiler,
                addr=addr,
                out_file=out_file,
                full=full,
                output_format=output_format,
            )
            if proc.returncode != 0:
                stderr_tail = (proc.stderr or "").strip()[-800:]
                parsed["error"] = stderr_tail or f"{decompiler} exited with code {proc.returncode}"
            parsed.setdefault("provider", "local")
            return parsed
    except subprocess.TimeoutExpired:
        return {"addr": addr, "code": "", "functions": [], "error": f"Timeout {decompiler} ({timeout}s)", "decompiler": decompiler}
    except Exception as exc:
        return {"addr": addr, "code": "", "functions": [], "error": str(exc), "decompiler": decompiler}


def _run_custom_decompiler_in_docker(
    decompiler: str,
    binary_path: str,
    *,
    addr: str = "",
    func_name: str = "",
    full: bool = False,
) -> dict[str, Any]:
    config = _load_custom_decompilers().get(_normalize_decompiler_id(decompiler))
    if not config:
        return {"addr": addr, "code": "", "functions": [], "error": f"Décompilateur custom inconnu : {decompiler}", "decompiler": decompiler, "provider": "docker"}
    image_name = _get_decompiler_docker_image(decompiler)
    if not image_name:
        return {"addr": addr, "code": "", "functions": [], "error": f"Aucune image Docker configurée pour {decompiler}", "decompiler": decompiler, "provider": "docker"}
    # Priorité : docker_full_command > docker_command > full_command > command
    command = config.get("docker_full_command") if full and config.get("docker_full_command") else config.get("docker_command")
    if not command:
        command = config.get("full_command") if full and config.get("full_command") else config.get("command")
    if full and not config.get("supports_full", True) and not config.get("docker_full_command") and not config.get("full_command"):
        return {"functions": [], "error": f"{decompiler} ne déclare pas supports_full", "decompiler": decompiler, "provider": "docker", "docker_image": image_name}
    if not isinstance(command, list) or not command:
        return {"addr": addr, "code": "", "functions": [], "error": f"Commande Docker custom invalide pour {decompiler}", "decompiler": decompiler, "provider": "docker", "docker_image": image_name}
    timeout = int(config.get("timeout") or (300 if full else 120))
    network = config.get("network", "none")
    output_format = config.get("output_format", "json")
    custom_env = config.get("env") or {}
    extra_docker_args = config.get("docker_extra_args") or []
    try:
        with tempfile.TemporaryDirectory(prefix="pof_custom_docker_") as tmp:
            binary_mount_dir, container_binary = _docker_mount_for_binary(binary_path)
            output_mount_dir, container_out = _docker_mount_for_output(tmp)
            out_ext = ".json" if output_format == "json" else ".c" if output_format == "c" else ".txt"
            # Adapter le chemin de sortie container selon l'extension
            container_out_path = f"/output/out{out_ext}"
            argv = _format_custom_command(
                [str(part) for part in command],
                binary_path=container_binary,
                addr=addr,
                func_name=func_name,
                mode="full" if full else "function",
                out_file=Path(container_out_path),
            )
            # Construire la commande docker run
            docker_exe = _find_docker_executable() or "docker"
            docker_cmd: list[str] = [docker_exe, "run", "--rm", "--network", network]
            # --platform : utilise POF_DOCKER_PLATFORM si défini (utile sur ARM / multi-arch)
            pof_platform = os.environ.get("POF_DOCKER_PLATFORM", "").strip()
            if pof_platform:
                docker_cmd += ["--platform", pof_platform]
            # Variables d'environnement
            for k, v in (custom_env.items() if isinstance(custom_env, dict) else []):
                docker_cmd += ["-e", f"{k}={v}"]
            # Volumes
            docker_cmd += ["-v", f"{binary_mount_dir}:/input:ro"]
            docker_cmd += ["-v", f"{output_mount_dir}:/output"]
            # Arguments supplémentaires
            docker_cmd += [str(a) for a in extra_docker_args]
            # Image + commande
            docker_cmd += [image_name, *argv]
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                timeout=timeout,
                text=True,
            )
            parsed = _parse_external_decompiler_output(
                proc.stdout,
                decompiler=decompiler,
                addr=addr,
                out_file=output_mount_dir / f"out{out_ext}",
                full=full,
                output_format=output_format,
            )
            parsed["provider"] = "docker"
            parsed["docker_image"] = image_name
            if proc.returncode != 0:
                stderr_tail = (proc.stderr or "").strip()[-800:]
                if _docker_run_failed_because_image_missing(stderr_tail):
                    _DOCKER_AVAILABLE_CACHE[image_name] = False
                    parsed["error"] = _docker_missing_image_error(decompiler, image_name)
                else:
                    parsed["error"] = stderr_tail or f"{decompiler} Docker exited with code {proc.returncode}"
            return parsed
    except subprocess.TimeoutExpired:
        return {"addr": addr, "code": "", "functions": [], "error": f"Timeout Docker {decompiler} ({timeout}s)", "decompiler": decompiler, "provider": "docker", "docker_image": image_name}
    except Exception as exc:
        return {"addr": addr, "code": "", "functions": [], "error": str(exc), "decompiler": decompiler, "provider": "docker", "docker_image": image_name}


def _cache_key(
    binary_path: str,
    addr: str,
    func_name: str = "",
    decompiler: str = "",
    annotations_json: str | None = None,
    stack_signature: str = "",
    typed_structs_signature: str = "",
    quality: str = "normal",
) -> str:
    """Clé de cache 16 hex chars."""
    binary_signature = _file_signature(binary_path) or binary_path
    ann_signature = _file_signature(annotations_json) or (annotations_json or "")
    raw = "|".join(
        [
            _DECOMPILE_CACHE_VERSION,
            binary_signature,
            addr.lower(),
            _normalize_symbol_lookup_name(func_name),
            decompiler,
            _normalize_quality(quality),
            ann_signature,
            stack_signature,
            typed_structs_signature,
        ]
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _read_cache(key: str, cache_dir: Path) -> dict | None:
    p = cache_dir / f"{key}.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _write_cache(key: str, cache_dir: Path, data: dict) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / f"{key}.json").write_text(
            json.dumps(data, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass  # cache write failure is non-fatal


_DEFAULT_CACHE_DIR = Path(__file__).resolve().parent.parent.parent / ".pile-ou-face" / "decompile_cache"


def _is_retdec_available() -> bool:
    return _find_retdec_executable() is not None


def _find_retdec_executable() -> str | None:
    found = shutil.which("retdec-decompiler")
    if found:
        return found
    install_dir = os.environ.get("RETDEC_INSTALL_DIR", "").strip()
    if install_dir:
        candidates = [
            Path(install_dir) / "retdec-decompiler",
            Path(install_dir) / "bin" / "retdec-decompiler",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
    return None


def _is_angr_available() -> bool:
    """Vérifie qu'angr est importable dans l'environnement Python courant."""
    try:
        import importlib.util
        return importlib.util.find_spec("angr") is not None
    except Exception:
        return False


def _find_boomerang_executable() -> str | None:
    """Cherche boomerang-cli dans PATH puis dans BOOMERANG_INSTALL_DIR."""
    found = shutil.which("boomerang-cli")
    if found:
        return found
    install_dir = os.environ.get("BOOMERANG_INSTALL_DIR", "").strip()
    if install_dir:
        candidates = [
            Path(install_dir) / "boomerang-cli",
            Path(install_dir) / "bin" / "boomerang-cli",
            Path(install_dir) / "build" / "bin" / "boomerang-cli",
        ]
        for c in candidates:
            if c.exists():
                return str(c)
    return None


def _is_boomerang_available() -> bool:
    return _find_boomerang_executable() is not None


def _is_r2_available() -> bool:
    return shutil.which("r2") is not None


def _is_r2ghidra_available() -> bool:
    """Vérifie si r2ghidra plugin est installé (r2pm -l | grep r2ghidra)."""
    if not _is_r2_available():
        return False
    try:
        result = subprocess.run(
            ["r2pm", "-l"], capture_output=True, timeout=10, text=True
        )
        if result.returncode == 0 and "r2ghidra" in result.stdout:
            return True
    except Exception:
        pass
    return False


def _find_ghidra_install_dir() -> str:
    """Trouve le répertoire d'installation Ghidra (libexec ou équivalent)."""
    import os, platform

    # 1. Variable d'environnement
    for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        d = os.environ.get(var, "")
        if d and (Path(d) / "Ghidra").exists():
            return d
    # 2. brew formula (keg)
    keg = Path("/opt/homebrew/opt/ghidra/libexec")
    if keg.exists():
        return str(keg)
    # 3. brew cask (legacy)
    cask = Path("/opt/homebrew/Caskroom/ghidra")
    if cask.exists():
        for p in sorted(cask.iterdir(), reverse=True):
            for sub in p.rglob("Ghidra"):
                if sub.is_dir():
                    return str(sub.parent)
    # 4. Linux/Windows fallbacks
    if platform.system() == "Linux":
        for d in ("/opt/ghidra", Path.home() / "ghidra"):
            if Path(d).exists():
                return str(d)
    return ""


def _is_ghidra_available() -> bool:
    """Ghidra est disponible si :
    1. le répertoire d'installation est trouvé, ET
    2. pyghidra est importable ET son JAR est présent dans l'install dir.
    La simple présence du dossier Ghidra ne suffit pas — pyghidra doit être
    correctement initialisé (python -m pyghidra install).
    """
    install_dir = _find_ghidra_install_dir()
    if not install_dir:
        return False
    jar_candidates = [
        Path(install_dir) / "Ghidra" / "Features" / "PyGhidra" / "lib" / "PyGhidra.jar",
        Path(install_dir) / "Ghidra" / "Extensions" / "PyGhidra" / "lib" / "PyGhidra.jar",
    ]
    if not any(candidate.exists() for candidate in jar_candidates):
        return False
    # Vérifier que pyghidra est importable dans l'environnement courant
    try:
        import importlib.util
        return importlib.util.find_spec("pyghidra") is not None
    except Exception:
        return False


def _find_docker_executable() -> str | None:
    env_candidate = os.environ.get("POF_DOCKER_BIN", "").strip()
    candidates = [
        env_candidate,
        shutil.which("docker"),
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        str(Path.home() / ".orbstack" / "bin" / "docker"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            if Path(candidate).exists():
                return candidate
        except Exception:
            continue
    return None


def _is_docker_decompiler_image_available(image: str) -> bool:
    """Return true when Docker can see a specific decompiler image locally."""
    image_name = str(image or "").strip()
    if not image_name:
        return False
    cached = _DOCKER_AVAILABLE_CACHE.get(image_name)
    # Cache only positive hits durably. A previously-missing local image may
    # appear later after `docker build`, while the backend process keeps
    # running, so negative cache entries must be revalidated.
    if cached is True:
        return cached
    docker_exe = _find_docker_executable()
    if not docker_exe:
        _DOCKER_AVAILABLE_CACHE[image_name] = False
        return False
    try:
        result = subprocess.run(
            [docker_exe, "image", "inspect", image_name],
            capture_output=True,
            timeout=4,
            text=True,
        )
        ok = result.returncode == 0
    except Exception:
        ok = False
    if ok:
        _DOCKER_AVAILABLE_CACHE[image_name] = True
    else:
        _DOCKER_AVAILABLE_CACHE.pop(image_name, None)
    return ok


def _is_docker_image_available_for_decompiler(decompiler: str) -> bool:
    return _is_docker_decompiler_image_available(_get_decompiler_docker_image(decompiler))


def _is_local_dev_docker_image(image_name: str) -> bool:
    normalized = str(image_name or "").strip().lower()
    return normalized.startswith("pile-ou-face/decompiler-")


def _docker_missing_image_error(decompiler: str, image_name: str) -> str:
    normalized = _normalize_decompiler_id(decompiler)
    lines = [f"Image Docker introuvable pour {decompiler} : {image_name}"]
    if _is_local_dev_docker_image(image_name):
        lines.append(f"Construis-la d'abord : make decompiler-docker-build DECOMPILER={normalized}")
        lines.append(
            f"Ou surcharge l'image avec {_docker_env_var_name_for_decompiler(normalized)}=registry/image:tag"
        )
    else:
        lines.append(f"Fais un docker pull {image_name} ou configure une image valide.")
    return "\n".join(lines)


def _docker_run_failed_because_image_missing(stderr: str) -> bool:
    normalized = str(stderr or "").lower()
    markers = (
        "unable to find image",
        "pull access denied",
        "repository does not exist",
        "requested access to the resource is denied",
        "manifest unknown",
        "not found",
    )
    return any(marker in normalized for marker in markers)


def _docker_mount_for_binary(binary_path: str) -> tuple[Path, str]:
    binary = Path(binary_path).resolve()
    mount_dir = binary.parent
    return mount_dir, f"/input/{binary.name}"


def _docker_mount_for_output(temp_dir: str) -> tuple[Path, str]:
    mount_dir = Path(temp_dir).resolve()
    return mount_dir, "/output/out.json"


def _preferred_docker_platform_for_decompiler(decompiler: str) -> str:
    forced = os.environ.get("POF_DOCKER_PLATFORM", "").strip()
    if forced:
        return forced
    return ""


def _run_builtin_decompiler_in_docker(
    decompiler: str,
    binary_path: str,
    *,
    addr: str = "",
    func_name: str = "",
    full: bool = False,
    quality: str = "normal",
) -> dict[str, Any]:
    image_name = _get_decompiler_docker_image(decompiler)
    if not image_name:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Aucune image Docker configurée pour {decompiler}",
            "decompiler": decompiler,
            "provider": "docker",
        }
    try:
        mount_dir, container_binary = _docker_mount_for_binary(binary_path)
        # Respecter POF_DOCKER_PLATFORM si défini, sinon laisser Docker choisir
        # l'image locale / la variante de manifeste la plus appropriée.
        pof_platform = _preferred_docker_platform_for_decompiler(decompiler)
        _platform_args = ["--platform", pof_platform] if pof_platform else []
        docker_exe = _find_docker_executable() or "docker"
        cmd = (
            [docker_exe, "run", "--rm"]
            + _platform_args
            + [
                "--network",
                "none",
                "-v",
                f"{mount_dir}:/input:ro",
                image_name,
                # Utilise le venv du container s'il existe, sinon python système
                "/opt/pof-venv/bin/python",
                "-m",
                "backends.static.decompile",
                "--provider",
                "local",
                "--decompiler",
                decompiler,
                "--quality",
                _normalize_quality(quality),
                "--binary",
                container_binary,
            ]
        )
        if full:
            cmd.append("--full")
        else:
            cmd.extend(["--addr", addr])
            if func_name:
                cmd.extend(["--func-name", func_name])
        proc = subprocess.run(cmd, capture_output=True, timeout=360, text=True)
        stdout = proc.stdout.strip()
        if not stdout:
            stderr_tail = (proc.stderr or "").strip()[-800:]
            if proc.returncode != 0 and _docker_run_failed_because_image_missing(stderr_tail):
                _DOCKER_AVAILABLE_CACHE[image_name] = False
                error_message = _docker_missing_image_error(decompiler, image_name)
            else:
                error_message = f"Docker {decompiler}: pas de sortie (rc={proc.returncode})" + (
                    f"\n{stderr_tail}" if stderr_tail else ""
                )
            return {
                "addr": addr,
                "code": "",
                "functions": [],
                "error": error_message,
                "decompiler": decompiler,
                "provider": "docker",
                "docker_image": image_name,
            }
        data = json.loads(stdout)
        if isinstance(data, dict):
            data.setdefault("decompiler", decompiler)
            data["provider"] = "docker"
            data.setdefault("docker_image", image_name)
            if proc.returncode != 0 and not data.get("error"):
                stderr_tail = (proc.stderr or "").strip()[-800:]
                if _docker_run_failed_because_image_missing(stderr_tail):
                    _DOCKER_AVAILABLE_CACHE[image_name] = False
                    data["error"] = _docker_missing_image_error(decompiler, image_name)
                else:
                    data["error"] = f"Docker {decompiler} exited with code {proc.returncode}"
            return data
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Docker {decompiler}: JSON inattendu",
            "decompiler": decompiler,
            "provider": "docker",
            "docker_image": image_name,
        }
    except subprocess.TimeoutExpired:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Timeout Docker {decompiler} (360s)",
            "decompiler": decompiler,
            "provider": "docker",
            "docker_image": image_name,
        }
    except Exception as exc:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": str(exc),
            "decompiler": decompiler,
            "provider": "docker",
            "docker_image": image_name,
        }


def _extract_pdc_c_column(raw: str) -> str:
    """Extraire la colonne pseudo-C de la sortie pdc de radare2.

    pdc produit des lignes larges : addr | asm ... addr | asm | pseudo-C
    On garde uniquement la derniere colonne (apres le dernier '|').
    """
    lines = []
    for line in raw.splitlines():
        if "|" in line:
            c_col = line.rsplit("|", 1)[-1].rstrip()
            if c_col.strip():
                lines.append(c_col)
        elif line.strip():
            lines.append(line)
    return "\n".join(lines)


def decompile_function_r2(binary_path: str, addr: str) -> dict[str, Any]:
    """Decompile une fonction via radare2 pdc (pseudo-C integre)."""
    base: dict[str, Any] = {
        "addr": addr,
        "code": "",
        "error": None,
        "decompiler": "r2pdc",
    }
    try:
        cmd = [
            "r2",
            "-q",
            "-e",
            "scr.color=0",
            "-e",
            "prj.name=",
            "-c",
            f"aa; s {addr}; pdc",
            binary_path,
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
        if result.returncode != 0:
            base["error"] = f"r2 exited with code {result.returncode}"
            return base
        output = _extract_pdc_c_column(result.stdout.strip())
        if not output:
            base["error"] = "r2 pdc: aucune sortie"
            return base
        base["code"] = output
    except subprocess.TimeoutExpired:
        base["error"] = "Timeout r2 (30s)"
        _log.warning("decompile_function_r2 timeout for %s at %s", binary_path, addr)
    except Exception as e:
        base["error"] = str(e)
        _log.warning("decompile_function_r2 error: %s", e)
    return base


def decompile_function_r2ghidra(binary_path: str, addr: str) -> dict[str, Any]:
    """Décompile une fonction via radare2 + plugin r2ghidra (pdg)."""
    base: dict[str, Any] = {
        "addr": addr,
        "code": "",
        "error": None,
        "decompiler": "r2ghidra",
    }
    try:
        cmd = [
            "r2",
            "-q",
            "-e",
            "scr.color=0",
            "-e",
            "prj.name=",
            "-c",
            f"aa; s {addr}; pdg",
            binary_path,
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=60, text=True)
        if result.returncode != 0:
            base["error"] = f"r2ghidra exited with code {result.returncode}"
            return base
        output = result.stdout.strip()
        if not output or "Unknown command" in result.stderr:
            base["error"] = "r2ghidra: plugin non installé ou aucune sortie"
            return base
        base["code"] = output
    except subprocess.TimeoutExpired:
        base["error"] = "Timeout r2ghidra (60s)"
        _log.warning(
            "decompile_function_r2ghidra timeout for %s at %s", binary_path, addr
        )
    except Exception as e:
        base["error"] = str(e)
        _log.warning("decompile_function_r2ghidra error: %s", e)
    return base


def decompile_binary_r2(binary_path: str) -> dict[str, Any]:
    """Decompile tout le binaire via radare2 pdca."""
    result: dict[str, Any] = {"code": "", "functions": [], "error": None, "decompiler": "r2pdc"}
    try:
        cmd = [
            "r2",
            "-q",
            "-e",
            "scr.color=0",
            "-e",
            "prj.name=",
            "-c",
            "aa; pdca",
            binary_path,
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
        if proc.returncode != 0:
            result["error"] = f"r2 exited with code {proc.returncode}"
            return result
        output = _extract_pdc_c_column(proc.stdout.strip())
        if not output:
            result["error"] = "r2 pdca: aucune sortie"
            return result
        result["code"] = output
        parsed_functions = _parse_c_like_function_blocks(output, binary_path=binary_path)
        if len(parsed_functions) > 1:
            result["functions"] = parsed_functions
            return result
        result["functions"] = _decompile_binary_via_function_targets(binary_path, decompile_function_r2)
        if result["functions"]:
            result["code"] = "\n\n".join(f["code"] for f in result["functions"] if f.get("code"))
    except subprocess.TimeoutExpired:
        result["error"] = "Timeout r2 (120s)"
        _log.warning("decompile_binary_r2 timeout for %s", binary_path)
    except Exception as e:
        result["error"] = str(e)
        _log.warning("decompile_binary_r2 error: %s", e)
    return result


def decompile_binary_r2ghidra(binary_path: str) -> dict[str, Any]:
    """Décompile tout le binaire via radare2 + r2ghidra (pdga)."""
    result: dict[str, Any] = {"code": "", "functions": [], "error": None, "decompiler": "r2ghidra"}
    try:
        cmd = [
            "r2",
            "-q",
            "-e",
            "scr.color=0",
            "-e",
            "prj.name=",
            "-c",
            "aa; pdg@@f",
            binary_path,
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=180, text=True)
        if proc.returncode != 0:
            result["error"] = f"r2ghidra exited with code {proc.returncode}"
            return result
        output = proc.stdout.strip()
        if not output or "Unknown command" in proc.stderr:
            result["error"] = "r2ghidra: plugin non installé ou aucune sortie"
            return result
        result["code"] = output
        result["functions"] = _parse_c_like_function_blocks(output, binary_path=binary_path)
    except subprocess.TimeoutExpired:
        result["error"] = "Timeout r2ghidra (180s)"
        _log.warning("decompile_binary_r2ghidra timeout for %s", binary_path)
    except Exception as e:
        result["error"] = str(e)
        _log.warning("decompile_binary_r2ghidra error: %s", e)
    return result


def _ghidra_import_decompile(binary_path: str, addr: str = "", func_name: str = "") -> list:
    """Appel direct à ghidra_decompile.decompile() dans le process courant.

    PyGhidra/JVM ne supporte pas d'être ré-initialisé dans un sous-process.
    On importe le module directement pour partager la JVM déjà démarrée.
    Utilise un cache de module pour éviter de ré-exécuter le code module à chaque appel.
    """
    import importlib.util
    import sys as _sys

    mod_name = "backends.static.ghidra_decompile"
    if mod_name in _sys.modules:
        mod = _sys.modules[mod_name]
    else:
        script_path = Path(__file__).parent / "ghidra_decompile.py"
        spec = importlib.util.spec_from_file_location(mod_name, str(script_path))
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        _sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod.decompile(binary_path, addr, func_name)


def decompile_function_ghidra(
    binary_path: str, addr: str, func_name: str = ""
) -> dict[str, Any]:
    """Décompile une fonction via PyGhidra (import direct, pas de subprocess JVM imbriqué)."""
    base: dict[str, Any] = {
        "addr": addr,
        "code": "",
        "error": None,
        "decompiler": "ghidra",
    }
    install_dir = _find_ghidra_install_dir()
    if not install_dir:
        base["error"] = (
            "Ghidra non trouvé — définir GHIDRA_INSTALL_DIR ou installer via brew"
        )
        return base
    os.environ.setdefault("GHIDRA_INSTALL_DIR", install_dir)
    try:
        data = _ghidra_import_decompile(binary_path, addr.lower(), func_name)
        if not data:
            base["error"] = "Ghidra: aucun résultat"
            return base
        first = data[0]
        if first.get("error"):
            base["error"] = f"Ghidra: {first['error']}"
            return base
        base["code"] = first.get("code", "")
    except Exception as e:
        base["error"] = str(e)
        _log.warning("decompile_function_ghidra error: %s", e)
    return base


def decompile_function_retdec(binary_path: str, addr: str, func_name: str = "") -> dict[str, Any]:
    base: dict[str, Any] = {
        "addr": addr,
        "code": "",
        "error": None,
        "decompiler": "retdec",
    }
    retdec_exe = _find_retdec_executable()
    if not retdec_exe:
        base["error"] = "retdec non trouvé — brew install retdec"
        return base
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out_c = Path(tmp) / "out.c"
            if func_name:
                select_args = ["--select-functions", func_name]
            else:
                start = int(addr, 16) if addr.startswith("0x") else int(addr, 10)
                end = start + 0x500
                select_args = ["--select-ranges", f"{addr}-{hex(end)}"]
            cmd = [retdec_exe] + select_args + ["-o", str(out_c), binary_path]
            subprocess.run(cmd, capture_output=True, timeout=30, check=True)
            if not out_c.exists():
                base["error"] = "retdec produced no output file"
                return base
            full_code = out_c.read_text(errors="replace")
            base["code"] = _extract_retdec_function_code(
                full_code,
                addr=addr,
                func_name=func_name,
            )
    except subprocess.TimeoutExpired:
        base["error"] = "Timeout retdec (30s)"
        _log.warning(
            "decompile_function_retdec timeout for %s at %s", binary_path, addr
        )
    except subprocess.CalledProcessError as e:
        base["error"] = f"retdec error: {e.returncode}"
        _log.warning("decompile_function_retdec error: %s", e)
    except Exception as e:
        base["error"] = str(e)
        _log.warning("decompile_function_retdec error: %s", e)
    return base


def _is_import_like_function_name(name: str) -> bool:
    normalized = str(name or "").strip()
    return normalized.startswith("sym.imp.")


def _build_symbol_alias_map(binary_path: str) -> dict[str, str]:
    alias_map: dict[str, str] = {}
    try:
        from backends.static.symbols import extract_symbols

        for sym in extract_symbols(binary_path):
            addr = _normalize_hex_addr(sym.get("addr"))
            raw_name = str(sym.get("name") or "").strip()
            if not addr or not raw_name:
                continue
            aliases = {raw_name}
            aliases.add(_pretty_symbol_name(raw_name))
            aliases.add(f"sym.{raw_name}")
            if raw_name.startswith("_"):
                aliases.add(raw_name[1:])
                aliases.add(f"sym.{raw_name[1:]}")
            for alias in aliases:
                alias = alias.strip()
                if alias:
                    alias_map.setdefault(alias, addr)
    except Exception:
        return {}
    return alias_map


def _normalize_symbol_lookup_name(name: str) -> str:
    symbol = _pretty_symbol_name(str(name or "").strip())
    if symbol.startswith("sym."):
        symbol = symbol.split("sym.", 1)[1]
    return symbol.strip().lower()


def _symbol_name_aliases(name: str) -> set[str]:
    raw_name = str(name or "").strip()
    aliases = {
        raw_name,
        _pretty_symbol_name(raw_name),
        _normalize_symbol_lookup_name(raw_name),
    }
    if raw_name.startswith("_") and len(raw_name) > 1:
        aliases.add(raw_name[1:])
        aliases.add(_normalize_symbol_lookup_name(raw_name[1:]))
    if raw_name.startswith("sym.") and len(raw_name) > 4:
        trimmed = raw_name.split("sym.", 1)[1]
        aliases.add(trimmed)
        aliases.add(_pretty_symbol_name(trimmed))
        aliases.add(_normalize_symbol_lookup_name(trimmed))
    return {alias.strip() for alias in aliases if str(alias or "").strip()}


def _build_function_target_index(binary_path: str) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    name_index: dict[str, dict[str, str]] = {}
    addr_index: dict[str, dict[str, str]] = {}

    def _add(addr: str, name: str) -> None:
        normalized_addr = _normalize_hex_addr(addr)
        raw_name = str(name or "").strip()
        if not normalized_addr or not raw_name:
            return
        entry = addr_index.setdefault(
            normalized_addr,
            {
                "addr": normalized_addr,
                "name": _pretty_symbol_name(raw_name) or raw_name,
                "raw_name": raw_name,
            },
        )
        for alias in _symbol_name_aliases(raw_name):
            name_index.setdefault(alias, entry)

    try:
        from backends.static.symbols import extract_symbols

        for sym in extract_symbols(binary_path):
            _add(str(sym.get("addr") or ""), str(sym.get("name") or ""))
    except Exception:
        pass

    try:
        for target in _collect_decompile_targets(binary_path):
            _add(str(target.get("addr") or ""), str(target.get("name") or ""))
    except Exception:
        pass

    return name_index, addr_index


def _resolve_function_target(binary_path: str, addr: str, func_name: str = "") -> tuple[str, str]:
    normalized_addr = _normalize_hex_addr(addr)
    wanted_name = str(func_name or "").strip()
    if not normalized_addr and not wanted_name:
        return normalized_addr, wanted_name

    name_index, addr_index = _build_function_target_index(binary_path)
    if wanted_name:
        resolved = name_index.get(_normalize_symbol_lookup_name(wanted_name))
        if resolved:
            normalized_addr = resolved["addr"]
            wanted_name = resolved.get("raw_name") or resolved.get("name") or wanted_name

    if normalized_addr:
        resolved = addr_index.get(normalized_addr)
        if resolved and not wanted_name:
            wanted_name = resolved.get("raw_name") or resolved.get("name") or wanted_name

    return normalized_addr or _normalize_hex_addr(addr), wanted_name


def _parse_c_like_function_blocks(
    code: str,
    *,
    binary_path: str = "",
    include_imports: bool = False,
) -> list[dict[str, Any]]:
    if not code:
        return []

    header_re = re.compile(
        r"^\s*(?P<header>(?:[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+(?P<name>(?:sym(?:\.imp)?\.)?[A-Za-z_][A-Za-z0-9_\.]*)\s*\([^;]*\))\s*(?:\{\s*)?$"
    )
    alias_map = _build_symbol_alias_map(binary_path) if binary_path else {}
    lines = code.splitlines()
    blocks: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        match = header_re.match(lines[i])
        if not match:
            i += 1
            continue
        name = str(match.group("name") or "").strip()
        if _is_import_like_function_name(name) and not include_imports:
            i += 1
            continue
        start = i
        brace_index = i
        if "{" not in lines[brace_index]:
            brace_index += 1
            while brace_index < len(lines) and "{" not in lines[brace_index]:
                if header_re.match(lines[brace_index]):
                    break
                brace_index += 1
        if brace_index >= len(lines) or "{" not in lines[brace_index]:
            i += 1
            continue
        depth = 0
        end = brace_index
        while end < len(lines):
            depth += lines[end].count("{")
            depth -= lines[end].count("}")
            if depth <= 0 and "}" in lines[end]:
                break
            end += 1
        if end >= len(lines):
            break
        block_code = "\n".join(lines[start : end + 1]).strip()
        if block_code:
            blocks.append(
                {
                    "addr": alias_map.get(name) or alias_map.get(_pretty_symbol_name(name), ""),
                    "code": block_code,
                    "error": None,
                    "name": _pretty_symbol_name(name),
                }
            )
        i = end + 1
    return blocks


def _collect_decompile_targets(binary_path: str) -> list[dict[str, str]]:
    try:
        from backends.static.disasm import disassemble_with_capstone
        from backends.static.discover_functions import discover_functions
        from backends.static.symbols import extract_symbols
    except Exception:
        return []

    lines = disassemble_with_capstone(binary_path) or []
    if not lines:
        return []
    line_addrs = {
        _normalize_hex_addr(line.get("addr"))
        for line in lines
        if _normalize_hex_addr(line.get("addr"))
    }
    symbol_name_by_addr: dict[str, str] = {}
    known_addrs: set[str] = set()
    for sym in extract_symbols(binary_path):
        addr = _normalize_hex_addr(sym.get("addr"))
        name = str(sym.get("name") or "").strip()
        if not addr or not name or addr not in line_addrs:
            continue
        if name.startswith("__") or name.endswith(".c"):
            continue
        known_addrs.add(addr)
        symbol_name_by_addr.setdefault(addr, name)

    targets: dict[str, str] = {
        addr: _pretty_symbol_name(name)
        for addr, name in symbol_name_by_addr.items()
        if not _is_import_like_function_name(name)
    }

    if not targets:
        try:
            for fn in discover_functions(lines, known_addrs, binary_path=binary_path):
                addr = _normalize_hex_addr(fn.get("addr"))
                if not addr or addr not in line_addrs:
                    continue
                confidence_score = float(fn.get("confidence_score") or 0.0)
                size = int(fn.get("size") or 0)
                kind = str(fn.get("kind") or "").strip().lower()
                if confidence_score < 0.8:
                    continue
                if size and size < 8:
                    continue
                if kind == "thunk" and size and size < 12:
                    continue
                targets.setdefault(addr, _pretty_symbol_name(fn.get("name") or addr))
        except Exception:
            pass

    return [
        {"addr": addr, "name": targets[addr]}
        for addr in sorted(targets, key=lambda value: int(value, 16))
    ]


def _decompile_binary_via_function_targets(binary_path: str, runner) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    for target in _collect_decompile_targets(binary_path):
        result = runner(binary_path, target["addr"])
        if result.get("error") or not result.get("code"):
            continue
        functions.append(
            {
                "addr": target["addr"],
                "code": result["code"],
                "error": None,
                "name": target.get("name") or "",
            }
        )
    return functions


def decompile_binary_ghidra(binary_path: str) -> dict[str, Any]:
    """Décompile tout le binaire via PyGhidra (import direct, pas de subprocess JVM imbriqué)."""
    result: dict[str, Any] = {"code": "", "functions": [], "error": None, "decompiler": "ghidra"}
    install_dir = _find_ghidra_install_dir()
    if not install_dir:
        result["error"] = (
            "Ghidra non trouvé — définir GHIDRA_INSTALL_DIR ou installer via brew"
        )
        return result
    os.environ.setdefault("GHIDRA_INSTALL_DIR", install_dir)
    try:
        data = _ghidra_import_decompile(binary_path)
        if not data:
            result["error"] = "Ghidra: aucune fonction reconnue par l'analyse Ghidra sur ce binaire"
            return result
        errors = [f["error"] for f in data if f.get("error")]
        if errors and len(errors) == len(data):
            result["error"] = f"Ghidra: {errors[0]}"
            return result
        result["functions"] = [
            {
                "addr": str(entry.get("addr") or ""),
                "code": str(entry.get("code") or ""),
                "error": entry.get("error"),
            }
            for entry in data
            if entry.get("code")
        ]
        result["code"] = "\n\n".join(f["code"] for f in data if f.get("code"))
    except Exception as e:
        result["error"] = str(e)
        _log.warning("decompile_binary_ghidra error: %s", e)
    return result


def decompile_binary_retdec(binary_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {"functions": [], "error": None, "decompiler": "retdec"}
    retdec_exe = _find_retdec_executable()
    if not retdec_exe:
        result["error"] = "retdec non trouvé — brew install retdec"
        return result
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out_c = Path(tmp) / "out.c"
            cmd = [retdec_exe, "-o", str(out_c), binary_path]
            subprocess.run(cmd, capture_output=True, timeout=120, check=True)
            if not out_c.exists():
                result["error"] = "retdec produced no output file"
                return result
            code = out_c.read_text(errors="replace")
            result["functions"] = _parse_retdec_output(code)
    except subprocess.TimeoutExpired:
        result["error"] = "Timeout retdec (120s)"
        _log.warning("decompile_binary_retdec timeout for %s", binary_path)
    except subprocess.CalledProcessError as e:
        result["error"] = f"retdec error: {e.returncode}"
        _log.warning("decompile_binary_retdec error: %s", e)
    except Exception as e:
        result["error"] = str(e)
        _log.warning("decompile_binary_retdec error: %s", e)
    return result


def _run_external_decompile_script(
    script_path: Path,
    binary_path: str,
    *,
    addr: str = "",
    full: bool = False,
    timeout: int = 180,
    decompiler: str = "",
) -> list[dict[str, Any]]:
    """Appelle un script externe *_decompile.py et retourne la liste JSON."""
    cmd = [sys.executable, str(script_path), "--binary", binary_path]
    if full:
        cmd.append("--full")
    elif addr:
        cmd.extend(["--addr", addr])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        stdout = proc.stdout.strip()
        if not stdout:
            stderr_tail = (proc.stderr or "").strip()[-800:]
            return [{"error": f"{decompiler}: pas de sortie (rc={proc.returncode})" + (f"\n{stderr_tail}" if stderr_tail else "")}]
        return json.loads(stdout)
    except subprocess.TimeoutExpired:
        return [{"error": f"Timeout {decompiler} ({timeout}s)"}]
    except Exception as exc:
        return [{"error": str(exc)}]


def decompile_function_angr(binary_path: str, addr: str) -> dict[str, Any]:
    """Décompile une fonction via angr."""
    base: dict[str, Any] = {"addr": addr, "code": "", "error": None, "decompiler": "angr"}
    script_path = Path(__file__).parent / "angr_decompile.py"
    if not _is_angr_available():
        base["error"] = "angr non installé — pip install angr"
        return base
    results = _run_external_decompile_script(
        script_path, binary_path, addr=addr, timeout=120, decompiler="angr"
    )
    if not results:
        base["error"] = "angr: aucun résultat"
        return base
    first = results[0]
    if first.get("error"):
        base["error"] = first["error"]
    else:
        base["code"] = first.get("code", "")
    return base


def decompile_binary_angr(binary_path: str) -> dict[str, Any]:
    """Décompile tout le binaire via angr."""
    result: dict[str, Any] = {"code": "", "functions": [], "error": None, "decompiler": "angr"}
    script_path = Path(__file__).parent / "angr_decompile.py"
    if not _is_angr_available():
        result["error"] = "angr non installé — pip install angr"
        return result
    items = _run_external_decompile_script(
        script_path, binary_path, full=True, timeout=300, decompiler="angr"
    )
    if not items:
        result["error"] = "angr: aucun résultat"
        return result
    if len(items) == 1 and items[0].get("error"):
        result["error"] = items[0]["error"]
        return result
    result["functions"] = [
        {"addr": str(f.get("addr") or ""), "code": str(f.get("code") or ""), "error": f.get("error")}
        for f in items if f.get("code")
    ]
    result["code"] = "\n\n".join(f["code"] for f in result["functions"] if f.get("code"))
    return result


def decompile_function_boomerang(binary_path: str, addr: str) -> dict[str, Any]:
    """Décompile une fonction via Boomerang."""
    base: dict[str, Any] = {"addr": addr, "code": "", "error": None, "decompiler": "boomerang"}
    script_path = Path(__file__).parent / "boomerang_decompile.py"
    if not _is_boomerang_available():
        base["error"] = "boomerang-cli non trouvé — définir BOOMERANG_INSTALL_DIR"
        return base
    results = _run_external_decompile_script(
        script_path, binary_path, addr=addr, timeout=180, decompiler="boomerang"
    )
    if not results:
        base["error"] = "boomerang: aucun résultat"
        return base
    first = results[0]
    if first.get("error"):
        base["error"] = first["error"]
    else:
        base["code"] = first.get("code", "")
    return base


def decompile_binary_boomerang(binary_path: str) -> dict[str, Any]:
    """Décompile tout le binaire via Boomerang."""
    result: dict[str, Any] = {"code": "", "functions": [], "error": None, "decompiler": "boomerang"}
    script_path = Path(__file__).parent / "boomerang_decompile.py"
    if not _is_boomerang_available():
        result["error"] = "boomerang-cli non trouvé — définir BOOMERANG_INSTALL_DIR"
        return result
    items = _run_external_decompile_script(
        script_path, binary_path, full=True, timeout=300, decompiler="boomerang"
    )
    if not items:
        result["error"] = "boomerang: aucun résultat"
        return result
    if len(items) == 1 and items[0].get("error"):
        result["error"] = items[0]["error"]
        return result
    result["functions"] = [
        {"addr": str(f.get("addr") or ""), "code": str(f.get("code") or ""), "error": f.get("error")}
        for f in items if f.get("code")
    ]
    result["code"] = "\n\n".join(f["code"] for f in result["functions"] if f.get("code"))
    return result


def _load_annotations_payload(annotations_json: str | None) -> tuple[dict[str, str], dict[str, str]]:
    """Charge ({addr_norm: name}, {addr_norm: comment}) depuis un fichier d'annotations."""
    if not annotations_json:
        return {}, {}
    try:
        data = json.loads(Path(annotations_json).read_text(encoding="utf-8"))
        names: dict[str, str] = {}
        comments: dict[str, str] = {}
        for addr_str, entry in data.items():
            if not isinstance(entry, dict):
                continue
            norm = addr_str.lower().lstrip("0x").lstrip("0") or "0"
            name = (entry.get("name") or "").strip()
            comment = (entry.get("comment") or "").strip()
            if name:
                names[norm] = name
            if comment:
                comments[norm] = comment
        return names, comments
    except Exception:
        return {}, {}


def _load_typed_struct_annotation_payload(binary_path: str) -> tuple[dict[str, str], dict[str, str], list[dict[str, Any]]]:
    try:
        index = build_typed_struct_index(binary_path)
    except Exception:
        return {}, {}, []
    names: dict[str, str] = {}
    comments: dict[str, str] = {}
    notes: list[dict[str, Any]] = []
    seen_notes: set[str] = set()
    for addr, entry in (index.get("exact_by_addr") or {}).items():
        norm = addr.lower().lstrip("0x").lstrip("0") or "0"
        label = str(entry.get("label") or "").strip()
        comment = str(entry.get("comment") or "").strip()
        if label:
            names[norm] = label
        if comment:
            comments[norm] = comment
        if entry.get("kind") != "field":
            continue
        key = f"{entry.get('struct_name')}:{entry.get('field_name')}:{addr}"
        if key in seen_notes:
            continue
        seen_notes.add(key)
        notes.append(
            {
                "addr": addr,
                "name": label or addr,
                "comment": comment,
                "struct_name": str(entry.get("struct_name") or "").strip(),
                "field_name": str(entry.get("field_name") or "").strip(),
                "field_type": str(entry.get("field_type") or "").strip(),
            }
        )
    return names, comments, notes


def _annotation_patterns(addr_norm: str) -> list[str]:
    hex_no0x = addr_norm.lower().lstrip("0") or "0"
    hex_with0x = f"0x{hex_no0x}"
    padded8 = hex_no0x.zfill(8)
    padded16 = hex_no0x.zfill(16)
    return [
        hex_with0x,
        f"fcn_{padded8}",
        f"fcn_{padded16}",
        f"sub_{padded8}",
        f"sub_{padded16}",
        f"FUN_{padded8}",
        f"FUN_{padded16}",
        f"fun_{padded8}",
        f"fun_{padded16}",
        f"DAT_{padded8}",
        f"DAT_{padded16}",
        f"LAB_{padded8}",
        f"LAB_{padded16}",
        f"PTR_{padded8}",
        f"PTR_{padded16}",
        f"code_{padded8}",
        f"code_{padded16}",
    ]


def _extract_call_names(code: str) -> set[str]:
    names: set[str] = set()
    for match in _CALL_NAME_RE.finditer(code or ""):
        name = (match.group(1) or "").strip()
        if not name or name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        names.add(name)
    return names


def _extract_reachable_call_names(
    binary_path: str,
    addr: str,
    *,
    instruction_map: dict[str, dict[str, Any]] | None = None,
    symbol_map: dict[str, str] | None = None,
    max_nodes: int = 256,
) -> set[str]:
    start_addr = _normalize_hex_addr(addr)
    if not start_addr:
        return set()
    if instruction_map is None or symbol_map is None:
        loaded_instruction_map, loaded_symbol_map = _load_r2pdc_cleanup_context(binary_path)
        if instruction_map is None:
            instruction_map = loaded_instruction_map
        if symbol_map is None:
            symbol_map = loaded_symbol_map
    if not instruction_map:
        return set()

    def _parse_target(operands: str) -> str:
        ops = str(operands or "").strip()
        if not ops:
            return ""
        match = re.search(r"0x[0-9a-f]+", ops, flags=re.IGNORECASE)
        return _normalize_hex_addr(match.group(0)) if match else ""

    def _is_return(ins: dict[str, Any]) -> bool:
        mnemonic = str(ins.get("mnemonic") or "").strip().lower()
        operands = str(ins.get("operands") or "").strip().lower()
        if mnemonic in {"ret", "retq", "retn"}:
            return True
        if mnemonic == "bx" and operands == "lr":
            return True
        if mnemonic == "pop" and "pc" in operands:
            return True
        return False

    def _successors(ins: dict[str, Any]) -> list[str]:
        mnemonic = str(ins.get("mnemonic") or "").strip().lower()
        operands = str(ins.get("operands") or "").strip()
        next_addr = _normalize_hex_addr(ins.get("next_addr"))
        target = _parse_target(operands)
        if _is_return(ins):
            return []
        if mnemonic in {"call", "callq", "bl", "blx"}:
            return [next_addr] if next_addr else []
        if mnemonic == "jmp" or mnemonic == "b":
            return [target] if target else []
        if mnemonic.startswith("j") and mnemonic != "jmp":
            return [item for item in (target, next_addr) if item]
        if mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}:
            return [item for item in (target, next_addr) if item]
        if re.fullmatch(r"b[a-z]{1,2}", mnemonic) and mnemonic not in {"bl", "blx", "bx"}:
            return [item for item in (target, next_addr) if item]
        return [next_addr] if next_addr else []

    queue = [start_addr]
    visited: set[str] = set()
    calls: set[str] = set()
    while queue and len(visited) < max_nodes:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        ins = instruction_map.get(current)
        if not ins:
            continue
        mnemonic = str(ins.get("mnemonic") or "").strip().lower()
        if mnemonic in {"call", "callq", "bl", "blx"}:
            target = _parse_target(ins.get("operands"))
            if target:
                calls.add(_pretty_symbol_name(symbol_map.get(target, target)).lower())
        for succ in _successors(ins):
            if succ and succ not in visited:
                queue.append(succ)
    return {
        name
        for name in calls
        if name and not re.fullmatch(r"0x[0-9a-f]+", name, flags=re.IGNORECASE)
    }


def _score_decompile_code(
    code: str,
    decompiler: str = "",
    *,
    expected_calls: set[str] | None = None,
    quality: str = "normal",
) -> dict[str, Any]:
    text = code or ""
    normalized_quality = _normalize_quality(quality)
    stripped_lines = [line.strip() for line in text.splitlines() if line.strip()]
    line_count = len(stripped_lines)
    call_names = {_pretty_symbol_name(name).lower() for name in _extract_call_names(text)}
    call_count = len(call_names)
    placeholder_count = len(_PLACEHOLDER_SYMBOL_RE.findall(text))
    control_count = sum(
        len(re.findall(rf"\b{kw}\b", text))
        for kw in ("if", "switch", "while", "for", "case", "return")
    )
    goto_count = len(re.findall(r"\bgoto\b", text))
    cast_count = len(re.findall(r"\([A-Za-z_][A-Za-z0-9_\s\*]*\)", text))
    type_hint_count = len(_TYPE_HINT_RE.findall(text))
    low_level_count = len(_LOW_LEVEL_PSEUDOC_RE.findall(text))
    warning_count = len(re.findall(r"//\s*WARNING:", text, flags=re.IGNORECASE))
    score = 0
    if normalized_quality == "precision":
        score += min(line_count, 56)
        score += min(call_count * 5, 28)
        score += min(control_count * 6, 36)
        score += min(type_hint_count, 8)
        score += min(cast_count, 4)
        score -= min(placeholder_count, 12)
        score -= min(goto_count, 4)
        score -= min(low_level_count, 8)
        score -= min(warning_count * 10, 30)
    else:
        score += min(line_count, 90)
        score += min(call_count * 4, 24)
        score += min(control_count * 5, 30)
        score += min(type_hint_count * 2, 16)
        score += min(cast_count, 8)
        score -= min(placeholder_count * 2, 24)
        score -= min(goto_count * 3, 12)
        score -= min(low_level_count * 2, 30)
        score -= min(warning_count * 8, 24)
    matched_call_count = 0
    missing_call_count = 0
    if expected_calls:
        normalized_expected = {
            _pretty_symbol_name(name).lower()
            for name in expected_calls
            if str(name or "").strip()
        }
        matched_call_count = len(call_names & normalized_expected)
        missing_call_count = len(normalized_expected - call_names)
        if normalized_quality == "precision":
            score += matched_call_count * 18
            score -= missing_call_count * 14
        else:
            score += matched_call_count * 12
            score -= missing_call_count * 6
    score += _quality_bias_for_backend(decompiler or "", normalized_quality)
    return {
        "score": score,
        "metrics": {
            "lines": line_count,
            "calls": call_count,
            "control": control_count,
            "type_hints": type_hint_count,
            "casts": cast_count,
            "placeholders": placeholder_count,
            "gotos": goto_count,
            "low_level": low_level_count,
            "warnings": warning_count,
            "matched_calls": matched_call_count,
            "missed_calls": missing_call_count,
            "quality_mode": normalized_quality,
        },
    }


def _score_binary_decompile(
    result: dict[str, Any], decompiler: str = "", quality: str = "normal"
) -> dict[str, Any]:
    normalized_quality = _normalize_quality(quality)
    functions = result.get("functions") or []
    fn_count = len(functions)
    total_code_len = sum(len((f.get("code") or "")) for f in functions if isinstance(f, dict))
    error_count = sum(1 for f in functions if isinstance(f, dict) and f.get("error"))
    if normalized_quality == "precision":
        score = fn_count * 14
        score += min(total_code_len // 150, 28)
        score -= error_count * 5
    else:
        score = fn_count * 12
        score += min(total_code_len // 120, 40)
        score -= error_count * 3
    score += _quality_bias_for_backend(decompiler or "", normalized_quality)
    return {
        "score": score,
        "metrics": {
            "functions": fn_count,
            "code_len": total_code_len,
            "errors": error_count,
            "quality_mode": normalized_quality,
        },
    }


def _build_quality_details(
    strategy: str,
    selected: dict[str, Any] | None,
    attempts: list[dict[str, Any]],
    scorer,
) -> dict[str, Any]:
    backend_rows: list[dict[str, Any]] = []
    selected_backend = selected.get("decompiler") if isinstance(selected, dict) else ""
    selected_score = None
    for attempt in attempts:
        backend = str(attempt.get("decompiler") or "")
        row: dict[str, Any] = {
            "decompiler": backend,
            "ok": not attempt.get("error") and bool(attempt.get("code") or attempt.get("functions")),
            "error": attempt.get("error") or None,
            "selected": bool(selected_backend and backend == selected_backend),
        }
        if row["ok"]:
            scored = scorer(attempt, backend)
            row["score"] = scored["score"]
            row["metrics"] = scored["metrics"]
            if row["selected"]:
                selected_score = scored["score"]
        backend_rows.append(row)
    return {
        "strategy": strategy,
        "selected_backend": selected_backend or "",
        "selected_score": selected_score,
        "backends": backend_rows,
    }


def _select_best_function_candidate(attempts: list[dict[str, Any]]) -> dict[str, Any] | None:
    successes = [attempt for attempt in attempts if not attempt.get("error") and attempt.get("code")]
    if not successes:
        return None
    scored = []
    for index, attempt in enumerate(successes):
        quality_score = attempt.get("_quality_score")
        if not isinstance(quality_score, int):
            quality = _score_decompile_code(attempt.get("code", ""), attempt.get("decompiler", ""))
            quality_score = quality["score"]
        scored.append((quality_score, -index, attempt))
    scored.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return scored[0][2]


def _select_best_binary_candidate(attempts: list[dict[str, Any]]) -> dict[str, Any] | None:
    successes = [attempt for attempt in attempts if not attempt.get("error") and attempt.get("functions")]
    if not successes:
        return None
    scored = []
    for index, attempt in enumerate(successes):
        quality_score = attempt.get("_quality_score")
        if not isinstance(quality_score, int):
            quality = _score_binary_decompile(attempt, attempt.get("decompiler", ""))
            quality_score = quality["score"]
        scored.append((quality_score, -index, attempt))
    scored.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return scored[0][2]


def _parse_numeric_token(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        return int(text, 16) if text.startswith("0x") or text.startswith("-0x") else int(text, 10)
    except ValueError:
        return None


def _normalize_hex_addr(value: str | int | None) -> str:
    parsed = _parse_numeric_token(value)
    return f"0x{parsed:x}" if parsed is not None else ""


def _pretty_symbol_name(name: str) -> str:
    symbol = str(name or "").strip()
    if symbol.startswith("sym.imp."):
        symbol = symbol.split("sym.imp.", 1)[1]
    if symbol.startswith("_") and re.fullmatch(r"_[A-Za-z][A-Za-z0-9_]*", symbol):
        return symbol[1:]
    return symbol


def _load_r2pdc_cleanup_context(binary_path: str) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    instruction_map: dict[str, dict[str, Any]] = {}
    symbol_map: dict[str, str] = {}
    try:
        from backends.static.disasm import disassemble_with_capstone

        lines = disassemble_with_capstone(binary_path) or []
        normalized_lines: list[dict[str, Any]] = []
        for line in lines:
            normalized = _normalize_hex_addr(line.get("addr"))
            if not normalized:
                continue
            copied = dict(line)
            copied["addr"] = normalized
            normalized_lines.append(copied)
        for index, line in enumerate(normalized_lines):
            next_addr = normalized_lines[index + 1]["addr"] if index + 1 < len(normalized_lines) else ""
            line["next_addr"] = next_addr
            instruction_map[line["addr"]] = line
    except Exception:
        instruction_map = {}
    try:
        from backends.static.symbols import extract_symbols

        for sym in extract_symbols(binary_path):
            addr = _normalize_hex_addr(sym.get("addr"))
            name = str(sym.get("name") or "").strip()
            if addr and name:
                symbol_map.setdefault(addr, name)
    except Exception:
        symbol_map = {}
    return instruction_map, symbol_map


def _simplify_pdc_assignment_value(line: str) -> str:
    text = str(line or "")
    string_literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)
    if string_literals:
        return f"\"{string_literals[-1]}\""
    rhs = text.split("=", 1)[-1].strip()
    rhs = rhs.split("//", 1)[0].strip()
    rhs = re.sub(r"\b(?:byte|word|dword|qword)\s*\[\s*([^\]]+?)\s*\]", r"\1", rhs, flags=re.IGNORECASE)
    return rhs.strip()


def _cleanup_r2pdc_code(
    code: str,
    binary_path: str = "",
    *,
    instruction_map: dict[str, dict[str, Any]] | None = None,
    symbol_map: dict[str, str] | None = None,
) -> str:
    if not code:
        return code
    if instruction_map is None or symbol_map is None:
        loaded_instruction_map, loaded_symbol_map = _load_r2pdc_cleanup_context(binary_path) if binary_path else ({}, {})
        if instruction_map is None:
            instruction_map = loaded_instruction_map
        if symbol_map is None:
            symbol_map = loaded_symbol_map

    raw_lines = code.splitlines()
    existing_labels = {
        match.group("label").lower()
        for line in raw_lines
        for match in [_PDC_LABEL_RE.match(line)]
        if match and "// orphan" not in line.lower()
    }

    cleaned_lines: list[str] = []
    skip_orphan_block = False
    for line in raw_lines:
        stripped = line.strip()
        label_match = _PDC_LABEL_RE.match(line)
        if label_match:
            skip_orphan_block = "// orphan" in line.lower()
            if skip_orphan_block:
                continue
        elif skip_orphan_block:
            continue

        if stripped.startswith("// callconv:"):
            continue
        if "CODE XREF" in stripped:
            continue
        line = re.sub(
            r"\b(?:byte|word|dword|qword)\s*\[\s*(var_[^\]]+|arg_[^\]]+)\s*\]",
            r"\1",
            line,
            flags=re.IGNORECASE,
        )
        line = re.sub(r"\bsym\.imp\.([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)", lambda m: f"{_pretty_symbol_name(m.group(1))}()", line)
        cleaned_lines.append(line)

    final_lines: list[str] = []
    i = 0
    while i < len(cleaned_lines):
        line = cleaned_lines[i]
        stripped = line.strip()

        goto_match = _PDC_GOTO_RE.match(line)
        if goto_match and goto_match.group("label").lower() not in existing_labels:
            target_addr = _normalize_hex_addr(goto_match.group("label").replace("loc_", ""))
            ins = instruction_map.get(target_addr or "")
            if ins and str(ins.get("mnemonic") or "").lower() == "call":
                callee_addr = _normalize_hex_addr(ins.get("operands"))
                callee_name = _pretty_symbol_name(symbol_map.get(callee_addr, callee_addr or "sub_call"))
                indent = goto_match.group("indent")
                final_lines.append(f"{indent}{callee_name}();")
                next_addr = _normalize_hex_addr(ins.get("next_addr"))
                next_ins = instruction_map.get(next_addr or "")
                if next_ins and str(next_ins.get("mnemonic") or "").lower() == "jmp":
                    jump_target = _normalize_hex_addr(next_ins.get("operands"))
                    if jump_target:
                        final_lines.append(f"{indent}goto loc_{jump_target};")
                i += 1
                continue

        if i + 3 < len(cleaned_lines):
            line_a = cleaned_lines[i].strip()
            line_b = cleaned_lines[i + 1].strip()
            line_c = cleaned_lines[i + 2].strip()
            line_d = cleaned_lines[i + 3].strip()
            call_match = re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?(?P<fn>[A-Za-z_][A-Za-z0-9_]*)\(\)(?:\s*//.*)?", line_d)
            if line_a.startswith("arg_rsi = ") and line_b.startswith("arg_rdi = ") and (line_c == "al = 0" or line_c.startswith("al = 0")) and call_match:
                fn_name = _pretty_symbol_name(call_match.group("fn"))
                arg2 = _simplify_pdc_assignment_value(line_a)
                arg1 = _simplify_pdc_assignment_value(line_b)
                indent = re.match(r"^(\s*)", cleaned_lines[i]).group(1)
                final_lines.append(f"{indent}{fn_name}({arg1}, {arg2});")
                i += 4
                continue

        if i + 1 < len(cleaned_lines):
            assign_line = cleaned_lines[i].strip()
            return_line = cleaned_lines[i + 1].strip()
            assign_match = re.fullmatch(r"(?:eax|rax)\s*=\s*(?P<expr>[A-Za-z_][A-Za-z0-9_]*)", assign_line)
            if assign_match and return_line in {"return rax;", "return eax;"}:
                indent = re.match(r"^(\s*)", cleaned_lines[i]).group(1)
                final_lines.append(f"{indent}return {assign_match.group('expr')};")
                i += 2
                continue

        if stripped == "return" and i + 1 < len(cleaned_lines) and cleaned_lines[i + 1].strip().startswith("return "):
            i += 1
            continue

        final_lines.append(line)
        i += 1

    first_body_index = next(
        (
            index
            for index, line in enumerate(final_lines)
            if line.strip() and line.strip() != "{" and not line.strip().startswith("int ") and not line.strip().startswith("void ")
        ),
        -1,
    )
    if first_body_index >= 0 and _PDC_LABEL_RE.match(final_lines[first_body_index]):
        del final_lines[first_body_index]

    stripped_noise = {
        "push (rbp)",
        "rbp = rsp",
        "push (ebp)",
        "ebp = esp",
        "rbp = pop ()",
        "ebp = pop ()",
    }
    normalized_lines: list[str] = []
    for line in final_lines:
        stripped = line.strip()
        if stripped in stripped_noise:
            continue
        if re.fullmatch(r"(?:rsp|esp|sp)\s*[-+]=\s*(?:0x[0-9a-f]+|\d+);?", stripped, flags=re.IGNORECASE):
            continue
        line = re.sub(
            r"^(\s*)(?:byte|word|dword|qword)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=",
            r"\1\2 =",
            line,
            flags=re.IGNORECASE,
        )
        normalized_lines.append(line)
    final_lines = normalized_lines

    structured_lines: list[str] = []
    i = 0
    while i < len(final_lines):
        if i + 5 < len(final_lines):
            assign_a = _PDC_ASSIGN_RE.match(final_lines[i])
            assign_b = _PDC_ASSIGN_RE.match(final_lines[i + 1])
            cond_line = final_lines[i + 2].strip()
            if assign_a and assign_b:
                lhs_name = assign_a.group("lhs")
                expr_name = assign_a.group("rhs").strip().rstrip(";")
                tmp_name = assign_b.group("lhs")
                rhs_expr = assign_b.group("rhs").strip().rstrip(";")
                sub_match = re.fullmatch(
                    rf"{re.escape(lhs_name)}\s*-\s*(?P<imm>0x[0-9a-f]+|\d+)(?:\s*//.*)?",
                    rhs_expr,
                    flags=re.IGNORECASE,
                )
                cond_match = re.fullmatch(
                    rf"if\s*\(\s*{re.escape(tmp_name)}\s*\)\s*goto\s+(?P<else_label>loc_0x[0-9a-f]+)(?:\s*//.*)?;?",
                    cond_line,
                    flags=re.IGNORECASE,
                )
                if sub_match and cond_match:
                    then_start = i + 3
                    then_end = then_start
                    end_goto = None
                    while then_end < len(final_lines):
                        goto_match = _PDC_GOTO_RE.match(final_lines[then_end])
                        if goto_match:
                            end_goto = goto_match
                            break
                        if _PDC_LABEL_RE.match(final_lines[then_end]):
                            break
                        then_end += 1
                    else_label_index = then_end + 1 if end_goto else -1
                    end_label = end_goto.group("label").lower() if end_goto else ""
                    if (
                        end_goto
                        and else_label_index < len(final_lines)
                        and (_PDC_LABEL_RE.match(final_lines[else_label_index]) or None)
                    ):
                        else_label_match = _PDC_LABEL_RE.match(final_lines[else_label_index])
                        if else_label_match and else_label_match.group("label").lower() == cond_match.group("else_label").lower():
                            else_body_start = else_label_index + 1
                            else_body_end = else_body_start
                            while else_body_end < len(final_lines):
                                label_match = _PDC_LABEL_RE.match(final_lines[else_body_end])
                                if label_match and label_match.group("label").lower() == end_label:
                                    break
                                else_body_end += 1
                            if else_body_end < len(final_lines):
                                indent = assign_a.group("indent")
                                then_body = [line.strip() for line in final_lines[then_start:then_end] if line.strip()]
                                else_body = [line.strip() for line in final_lines[else_body_start:else_body_end] if line.strip()]
                                structured_lines.append(f"{indent}if ({expr_name} == {sub_match.group('imm')}) {{")
                                for body_line in then_body:
                                    structured_lines.append(f"{indent}    {body_line}")
                                structured_lines.append(f"{indent}}} else {{")
                                for body_line in else_body:
                                    structured_lines.append(f"{indent}    {body_line}")
                                structured_lines.append(f"{indent}}}")
                                i = else_body_end + 1
                                continue

        structured_lines.append(final_lines[i])
        i += 1
    final_lines = structured_lines

    referenced_labels = {
        match.group(1).lower()
        for line in final_lines
        for match in re.finditer(r"\bgoto\s+(loc_0x[0-9a-f]+)\b", line, flags=re.IGNORECASE)
    }
    final_lines = [
        line
        for line in final_lines
        if not (_PDC_LABEL_RE.match(line) and _PDC_LABEL_RE.match(line).group("label").lower() not in referenced_labels)
    ]

    code_snapshot = "\n".join(final_lines)
    trimmed_lines: list[str] = []
    for line in final_lines:
        assign_match = _PDC_ASSIGN_RE.match(line)
        if assign_match:
            lhs = assign_match.group("lhs")
            rhs = assign_match.group("rhs").strip().rstrip(";")
            if re.fullmatch(r"arg_[A-Za-z0-9_]+(?:\s*//.*)?", rhs) and not re.search(rf"\b{re.escape(lhs)}\b", code_snapshot.replace(line, "", 1)):
                continue
        trimmed_lines.append(line)
    final_lines = trimmed_lines

    code_snapshot = "\n".join(final_lines)
    constant_assignments: dict[str, str] = {}
    for line in final_lines:
        assign_match = _PDC_ASSIGN_RE.match(line)
        if assign_match:
            rhs = assign_match.group("rhs").strip().rstrip(";")
            if re.fullmatch(r"0x[0-9a-f]+|\d+", rhs, flags=re.IGNORECASE):
                constant_assignments[assign_match.group("lhs")] = rhs
    simplified_lines: list[str] = []
    for line in final_lines:
        assign_match = _PDC_ASSIGN_RE.match(line)
        if assign_match:
            lhs = assign_match.group("lhs")
            rhs = assign_match.group("rhs").strip().rstrip(";")
            if (
                lhs in constant_assignments
                and rhs == constant_assignments[lhs]
                and re.search(rf"\breturn\s+{re.escape(lhs)}\b", code_snapshot)
                and len(re.findall(rf"\b{re.escape(lhs)}\b", code_snapshot)) <= 2
            ):
                continue
        line = re.sub(
            r"\breturn\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
            lambda m: f"return {constant_assignments.get(m.group(1), m.group(1))};",
            line,
        )
        simplified_lines.append(line)
    final_lines = simplified_lines

    return_simplified: list[str] = []
    i = 0
    while i < len(final_lines):
        if i + 1 < len(final_lines):
            assign_match = _PDC_ASSIGN_RE.match(final_lines[i])
            return_line = final_lines[i + 1].strip().rstrip(";")
            if assign_match and return_line in {"return rax", "return eax"}:
                indent = assign_match.group("indent")
                return_simplified.append(f"{indent}return {assign_match.group('rhs').strip().rstrip(';')}")
                i += 2
                continue
        return_simplified.append(final_lines[i])
        i += 1
    final_lines = return_simplified
    final_lines = [
        re.sub(
            r"\breturn\s+([A-Za-z_][A-Za-z0-9_]*)\b",
            lambda m: f"return {constant_assignments.get(m.group(1), m.group(1))}",
            line,
        )
        for line in final_lines
    ]
    compact_lines: list[str] = []
    for index, line in enumerate(final_lines):
        assign_match = _PDC_ASSIGN_RE.match(line)
        if assign_match:
            lhs = assign_match.group("lhs")
            remaining = "\n".join(final_lines[index + 1 :])
            if lhs and not re.search(rf"\b{re.escape(lhs)}\b", remaining):
                continue
        compact_lines.append(line)
    final_lines = compact_lines

    with_semicolons: list[str] = []
    for line in final_lines:
        stripped = line.strip()
        if (
            stripped
            and not stripped.endswith((";", "{", "}", ":"))
            and not stripped.startswith("//")
        ):
            line = f"{line};"
        with_semicolons.append(line)
    if sum(line.count("{") for line in with_semicolons) > sum(line.count("}") for line in with_semicolons):
        with_semicolons.append("}")
    final_lines = with_semicolons

    return "\n".join(final_lines).strip()


_X86_REGISTER_ALIASES: dict[str, tuple[str, ...]] = {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
    "r8": ("r8", "r8d", "r8w", "r8b"),
    "r9": ("r9", "r9d", "r9w", "r9b"),
}


def _canonicalize_stack_base(base: str) -> str:
    normalized = str(base or "").strip().lower()
    if normalized == "fp":
        return "r11"
    return normalized


def _canonicalize_stack_location(location: str) -> str:
    match = re.fullmatch(
        r"\[(?P<base>rbp|ebp|rsp|esp|sp|x29|r11|fp)(?:(?P<sign>[+\-])(?P<off>0x[0-9a-f]+|\d+))?\]",
        str(location or "").strip().lower(),
        flags=re.IGNORECASE,
    )
    if not match:
        return str(location or "").strip().lower()
    base = _canonicalize_stack_base(match.group("base"))
    sign = match.group("sign")
    off = _parse_numeric_token(match.group("off") or "0") or 0
    if sign == "-":
        off = -off
    if off == 0:
        return f"[{base}]"
    sign = "+" if off > 0 else "-"
    return f"[{base}{sign}0x{abs(off):x}]"


def _register_aliases(location: str) -> tuple[str, ...]:
    normalized = str(location or "").strip().lower()
    if not normalized:
        return ()
    if normalized in _X86_REGISTER_ALIASES:
        return _X86_REGISTER_ALIASES[normalized]
    if re.fullmatch(r"x\d+", normalized):
        suffix = normalized[1:]
        return (normalized, f"w{suffix}")
    if re.fullmatch(r"w\d+", normalized):
        suffix = normalized[1:]
        return (f"x{suffix}", normalized)
    if re.fullmatch(r"r\d+", normalized):
        return (normalized,)
    return (normalized,)


def _canonicalize_stack_entries(entries: list[dict] | None) -> list[dict]:
    normalized: list[dict] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        normalized.append(
            {
                "name": str(entry.get("name") or ""),
                "offset": entry.get("offset"),
                "size": entry.get("size"),
                "source": str(entry.get("source") or ""),
                "location": str(entry.get("location") or ""),
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            item["name"],
            item["location"],
            item["offset"] if isinstance(item["offset"], int) else 0,
            item["size"] if isinstance(item["size"], int) else 0,
            item["source"],
        ),
    )


def _stack_token_aliases(stack_vars: list[dict] | None) -> dict[str, str]:
    """Construit des alias de variables selon les conventions des décompilateurs.

    Exemples:
    - Ghidra/r2ghidra: local_10, auStack_18, puStack_20
    - r2pdc/IDA-like: var_8h, arg_10h
    - générique: param_1, param_2
    """
    aliases: dict[str, str] = {}
    ordered_args: list[str] = []

    def _remember(alias: str, name: str) -> None:
        alias = str(alias or "").strip()
        name = str(name or "").strip()
        if not alias or not name or alias == name:
            return
        aliases.setdefault(alias, name)

    for entry in stack_vars or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        offset = entry.get("offset")
        size = _parse_numeric_token(entry.get("size"))
        source = str(entry.get("source") or "").strip().lower()
        is_arg = source == "abi"
        if not is_arg and isinstance(offset, int):
            is_arg = offset >= 0
        if is_arg:
            ordered_args.append(name)

        if not isinstance(offset, int):
            continue

        abs_hex = f"{abs(offset):x}"
        abs_dec = str(abs(offset))
        if offset < 0:
            for prefix in ("local_", "uStack_", "iStack_", "puStack_", "auStack_"):
                _remember(f"{prefix}{abs_hex}", name)
                _remember(f"{prefix}{abs_dec}", name)
            _remember(f"var_{abs_hex}h", name)
            _remember(f"var_{abs_hex}", name)
            _remember(f"stack0x{((1 << 32) + offset):x}", name)
            _remember(f"stack0x{((1 << 64) + offset):x}", name)
            if size:
                _remember(f"local_res{size}", name)
        elif offset > 0:
            _remember(f"arg_{abs_hex}h", name)
            _remember(f"arg_{abs_hex}", name)
            _remember(f"arg_{abs_dec}", name)
            _remember(f"stack0x{offset:x}", name)

    for index, name in enumerate(ordered_args, start=1):
        _remember(f"param_{index}", name)

    return aliases


def _stack_frame_payload(
    stack_frame: dict[str, Any] | None, stack_vars: list[dict] | None
) -> dict[str, Any] | None:
    if stack_frame:
        return {
            "arch": stack_frame.get("arch") or "unknown",
            "abi": stack_frame.get("abi") or "unknown",
            "frame_size": int(stack_frame.get("frame_size") or 0),
            "vars": _canonicalize_stack_entries(stack_frame.get("vars")),
            "args": _canonicalize_stack_entries(stack_frame.get("args")),
        }
    if not stack_vars:
        return None

    args: list[dict] = []
    vars_: list[dict] = []
    for entry in _canonicalize_stack_entries(stack_vars):
        is_arg = entry.get("source") == "abi"
        if not is_arg and isinstance(entry.get("offset"), int):
            is_arg = entry["offset"] >= 0
        (args if is_arg else vars_).append(entry)
    return {
        "arch": "unknown",
        "abi": "unknown",
        "frame_size": 0,
        "vars": vars_,
        "args": args,
    }


def _stack_signature(stack_frame: dict[str, Any] | None, stack_vars: list[dict] | None) -> str:
    payload = _stack_frame_payload(stack_frame, stack_vars)
    if not payload:
        return ""
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _postprocess_code(
    code: str,
    annotations_map: dict[str, str],
    stack_vars: list[dict] | None = None,
    *,
    binary_path: str = "",
    addr: str = "",
    decompiler: str = "",
) -> str:
    """Post-traitement du pseudo-C : injecte les noms d'annotations et variables de stack.

    Args:
        code: Pseudo-C brut du décompilateur
        annotations_map: {addr_hex_norm: name} (adresses sans préfixe 0x, lowercase)
        stack_vars: Optionnel, liste de {name, offset} depuis stack_frame.py

    Returns:
        Pseudo-C enrichi avec les noms symboliques.
    """
    if not code:
        return code

    # 1. Inject annotation names: replace 0xADDR, fcn_ADDR, sub_ADDR, FUN_ADDR
    for addr_norm, name in annotations_map.items():
        for pattern in _annotation_patterns(addr_norm):
            code = re.sub(re.escape(pattern), name, code, flags=re.IGNORECASE)

    # 2. Stack variable substitution: *(uintN_t *)(rbp - 0xN) → var_name
    if stack_vars:
        offset_to_name: dict[int, str] = {}
        raw_expr_to_name: dict[tuple[str, str, int], str] = {}
        register_name_map: dict[str, str] = {}
        stack_token_aliases = _stack_token_aliases(stack_vars)
        for v in stack_vars:
            off = v.get("offset")
            vname = v.get("name", "")
            if off is not None and vname:
                offset_to_name[int(off)] = vname
            location = _canonicalize_stack_location(v.get("location") or "")
            match = re.fullmatch(
                r"\[(?P<base>rbp|ebp|rsp|esp|sp|x29|r11)(?:(?P<sign>[+\-])(?P<off>0x[0-9a-f]+|\d+))?\]",
                location,
                flags=re.IGNORECASE,
            )
            if match and vname:
                off_value = _parse_numeric_token(match.group("off") or "0") or 0
                raw_expr_to_name[
                    (match.group("base").lower(), match.group("sign") or "+", off_value)
                ] = vname
            if vname and location and not location.startswith("["):
                for alias in _register_aliases(location):
                    register_name_map[alias] = vname

        def _replace_stack_ref(m: re.Match) -> str:
            base = _canonicalize_stack_base(m.group("base"))
            sign = m.group("sign")
            off_int = _parse_numeric_token(m.group("off")) or 0
            direct = raw_expr_to_name.get((base, sign, off_int))
            if direct:
                return direct
            actual = -off_int if sign == "-" else off_int
            return offset_to_name.get(actual, m.group(0))

        # Pattern: (rbp|rsp|sp|x29) ± N inside a cast or array index
        stack_re = re.compile(
            r"\((?P<base>rbp|ebp|rsp|esp|sp|x29|r11|fp)\s*(?P<sign>[+\-])\s*(?P<off>0x[0-9a-fA-F]+|\d+)\)",
            flags=re.IGNORECASE,
        )
        code = stack_re.sub(_replace_stack_ref, code)
        for alias, stack_name in sorted(
            stack_token_aliases.items(),
            key=lambda item: (-len(item[0]), item[0]),
        ):
            code = re.sub(
                rf"\b{re.escape(alias)}\b",
                stack_name,
                code,
                flags=re.IGNORECASE,
            )
        for reg_name, arg_name in sorted(register_name_map.items(), key=lambda item: (-len(item[0]), item[0])):
            code = re.sub(
                rf"\b{re.escape(reg_name)}\b",
                arg_name,
                code,
                flags=re.IGNORECASE,
            )

    if decompiler == "r2pdc":
        code = _cleanup_r2pdc_code(code, binary_path)

    return code


def _collect_annotation_notes(
    raw_code: str,
    annotations_map: dict[str, str],
    annotation_comments: dict[str, str],
) -> list[dict[str, str]]:
    """Retourne les annotations référencées par le pseudo-C avec leurs commentaires."""
    notes: list[dict[str, str]] = []
    seen: set[str] = set()
    for addr_norm, name in annotations_map.items():
        matched = any(
            re.search(re.escape(pattern), raw_code, flags=re.IGNORECASE)
            for pattern in _annotation_patterns(addr_norm)
        )
        if not matched:
            continue
        key = f"{addr_norm}:{name}"
        if key in seen:
            continue
        seen.add(key)
        notes.append(
            {
                "addr": f"0x{addr_norm}",
                "name": name,
                "comment": annotation_comments.get(addr_norm, ""),
            }
        )
    return notes


def _collect_typed_struct_notes(
    raw_code: str,
    struct_notes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in struct_notes or []:
        addr_norm = str(entry.get("addr") or "").lower().lstrip("0x").lstrip("0") or "0"
        matched = any(
            re.search(re.escape(pattern), raw_code, flags=re.IGNORECASE)
            for pattern in _annotation_patterns(addr_norm)
        )
        if not matched:
            continue
        key = f"{entry.get('struct_name')}:{entry.get('field_name')}:{addr_norm}"
        if key in seen:
            continue
        seen.add(key)
        notes.append(dict(entry))
    return notes


def _normalize_provider(provider: str | None) -> str:
    normalized = str(provider or "auto").strip().lower()
    if normalized in {"local", "docker", "auto"}:
        return normalized
    return "auto"


def _is_builtin_available_local(decompiler: str) -> bool:
    if decompiler == "ghidra":
        return _is_ghidra_available()
    if decompiler == "retdec":
        return _is_retdec_available()
    if decompiler == "angr":
        return _is_angr_available()
    return False


def _is_decompiler_available(decompiler: str, provider: str = "auto") -> bool:
    provider = _normalize_provider(provider)
    decompiler = _normalize_decompiler_id(decompiler)
    if decompiler in _load_custom_decompilers():
        if provider == "docker":
            return _is_docker_image_available_for_decompiler(decompiler)
        return True
    if decompiler not in _BUILTIN_DECOMPILERS:
        return False
    if provider == "local":
        return _is_builtin_available_local(decompiler)
    if provider == "docker":
        return _is_docker_image_available_for_decompiler(decompiler)
    return _is_builtin_available_local(decompiler) or _is_docker_image_available_for_decompiler(decompiler)


def _run_builtin_function_decompiler(
    decompiler: str,
    binary_path: str,
    addr: str,
    *,
    func_name: str = "",
    provider: str = "auto",
    quality: str = "normal",
) -> dict[str, Any]:
    provider = _normalize_provider(provider)

    def _local() -> dict[str, Any]:
        if decompiler == "ghidra":
            return decompile_function_ghidra(binary_path, addr, func_name=func_name)
        if decompiler == "retdec":
            return decompile_function_retdec(binary_path, addr, func_name=func_name)
        if decompiler == "angr":
            return decompile_function_angr(binary_path, addr)
        return {"addr": addr, "code": "", "error": f"Décompilateur inconnu : {decompiler}", "decompiler": decompiler}

    if provider == "local":
        out = _local()
        out.setdefault("provider", "local")
        return out
    if provider == "docker":
        return _run_builtin_decompiler_in_docker(
            decompiler,
            binary_path,
            addr=addr,
            func_name=func_name,
            full=False,
            quality=quality,
        )
    if _is_builtin_available_local(decompiler):
        out = _local()
        out.setdefault("provider", "local")
        if not out.get("error"):
            return out
        _log.warning("%s local failed (%s), trying docker", decompiler, out.get("error"))
    if not _is_docker_image_available_for_decompiler(decompiler):
        out = _local()
        out.setdefault("provider", "local")
        return out
    return _run_builtin_decompiler_in_docker(
        decompiler,
        binary_path,
        addr=addr,
        func_name=func_name,
        full=False,
        quality=quality,
    )


def _run_builtin_binary_decompiler(
    decompiler: str,
    binary_path: str,
    *,
    provider: str = "auto",
    quality: str = "normal",
) -> dict[str, Any]:
    provider = _normalize_provider(provider)

    def _local() -> dict[str, Any]:
        if decompiler == "ghidra":
            return decompile_binary_ghidra(binary_path)
        if decompiler == "retdec":
            return decompile_binary_retdec(binary_path)
        if decompiler == "angr":
            return decompile_binary_angr(binary_path)
        return {"functions": [], "error": f"Décompilateur inconnu : {decompiler}", "decompiler": decompiler}

    if provider == "local":
        out = _local()
        out.setdefault("provider", "local")
        return out
    if provider == "docker":
        return _run_builtin_decompiler_in_docker(
            decompiler,
            binary_path,
            full=True,
            quality=quality,
        )
    if _is_builtin_available_local(decompiler):
        out = _local()
        out.setdefault("provider", "local")
        if not out.get("error"):
            return out
        _log.warning("%s binary local failed (%s), trying docker", decompiler, out.get("error"))
    if not _is_docker_image_available_for_decompiler(decompiler):
        out = _local()
        out.setdefault("provider", "local")
        return out
    return _run_builtin_decompiler_in_docker(
        decompiler,
        binary_path,
        full=True,
        quality=quality,
    )


def _load_hidden_builtins(config_path: Path | None = None) -> list[str]:
    """Charge la liste des builtins masqués depuis decompilers.json."""
    env_path = os.environ.get("POF_DECOMPILERS_CONFIG", "").strip()
    cfg_path = config_path or (Path(env_path) if env_path else _CUSTOM_DECOMPILERS_CONFIG)
    try:
        raw = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    except Exception:
        return []
    hidden = raw.get("hidden_builtins", [])
    if not isinstance(hidden, list):
        return []
    return [str(bid) for bid in hidden if str(bid) in _BUILTIN_DECOMPILERS]


def _save_hidden_builtins(hidden: list[str], config_path: Path | None = None) -> None:
    """Persiste la liste des builtins masqués dans decompilers.json."""
    env_path = os.environ.get("POF_DECOMPILERS_CONFIG", "").strip()
    cfg_path = config_path or (Path(env_path) if env_path else _CUSTOM_DECOMPILERS_CONFIG)
    try:
        cfg_path = Path(cfg_path)
        if cfg_path.exists():
            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        else:
            raw = {}
        raw["hidden_builtins"] = hidden
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        _log.warning("Impossible d'enregistrer hidden_builtins : %s", exc)


def list_available_decompilers(provider: str = "auto") -> dict[str, Any]:
    """Retourne les décompilateurs disponibles, incluant Docker et custom.

    Le booléen de premier niveau (ex: available["ghidra"]) indique si le décompilateur
    est utilisable selon le provider demandé.

    Les builtins présents dans hidden_builtins (decompilers.json) sont exclus
    de la liste principale mais signalés dans _meta.hidden_builtins pour l'UI.

    _meta.local_available  : dict id -> bool (disponibilité locale réelle)
    _meta.docker_images_available : dict id -> bool (image Docker présente)
    Ces deux dicts sont toujours calculés indépendamment du provider pour
    permettre un affichage de badges précis dans l'UI.
    """
    provider = _normalize_provider(provider)
    docker_images = _get_all_docker_images()

    ALL_BUILTIN_IDS = list(_CURATED_BUILTIN_DECOMPILERS)
    hidden_builtins = [
        bid for bid in _load_hidden_builtins()
        if bid not in _CURATED_BUILTIN_DECOMPILERS
    ]
    # Seuls les builtins non masqués sont exposés
    BUILTIN_IDS = [bid for bid in ALL_BUILTIN_IDS if bid not in hidden_builtins]

    # Disponibilité locale stricte (sans fallback Docker)
    local_available: dict[str, bool] = {
        bid: _is_builtin_available_local(bid) for bid in BUILTIN_IDS
    }
    # Disponibilité Docker (image présente localement)
    docker_avail: dict[str, bool] = {
        key: _is_docker_decompiler_image_available(image)
        for key, image in docker_images.items()
    }

    available: dict[str, Any] = {
        bid: _is_decompiler_available(bid, provider) for bid in BUILTIN_IDS
    }
    for key in _load_custom_decompilers():
        available[key] = _is_decompiler_available(key, provider)
        local_available[key] = True  # custom déclaré = considéré présent localement

    available["_meta"] = {
        "provider": provider,
        "docker_images": docker_images,
        "docker_images_available": docker_avail,
        "local_available": local_available,
        "custom_labels": _custom_decompiler_labels(),
        "hidden_builtins": hidden_builtins,
    }
    return available


def _parse_retdec_function_blocks(c_code: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"// Address range:\s*(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s*\n"
        r"(.*?)(?=(?:\n// Address range:|\n// --------------------- Meta-Information ---------------------|$))",
        flags=re.DOTALL,
    )
    functions: list[dict[str, Any]] = []
    for match in pattern.finditer(c_code or ""):
        addr = match.group(1)
        end_addr = match.group(2)
        code = (match.group(3) or "").strip()
        if code:
            functions.append(
                {
                    "addr": addr,
                    "end_addr": end_addr,
                    "code": code,
                    "error": None,
                }
            )
    return functions


def _parse_retdec_output(c_code: str) -> list[dict[str, Any]]:
    """Découpe le .c retdec en fonctions par commentaire // Address range: 0x..."""
    return [
        {"addr": entry["addr"], "code": entry["code"], "error": None}
        for entry in _parse_retdec_function_blocks(c_code)
    ]


def _extract_retdec_function_code(
    c_code: str, addr: str = "", func_name: str = ""
) -> str:
    normalized_addr = _normalize_hex_addr(addr)
    wanted_name = str(func_name or "").strip()
    blocks = _parse_retdec_function_blocks(c_code)
    if not blocks:
        return c_code
    if normalized_addr:
        for block in blocks:
            if _normalize_hex_addr(block.get("addr")) == normalized_addr:
                return block.get("code") or c_code
    if wanted_name:
        name_pattern = re.compile(rf"\b{re.escape(wanted_name)}\s*\(")
        for block in blocks:
            if name_pattern.search(block.get("code") or ""):
                return block.get("code") or c_code
    if len(blocks) == 1:
        return blocks[0].get("code") or c_code
    return c_code


def _auto_function_decompiler_order(quality: str) -> list[str]:
    normalized = _normalize_quality(quality)
    custom = list(_load_custom_decompilers())
    if normalized == "precision":
        return ["retdec", "ghidra", *custom, "angr"]
    return ["ghidra", "retdec", *custom, "angr"]


def _auto_binary_decompiler_order(quality: str) -> list[str]:
    normalized = _normalize_quality(quality)
    custom = list(_load_custom_decompilers())
    if normalized == "precision":
        return ["retdec", "ghidra", *custom, "angr"]
    return ["ghidra", "retdec", *custom, "angr"]


def decompile_function(
    binary_path: str,
    addr: str,
    func_name: str = "",
    arch: str = "x86_64",
    decompiler: str = "",
    annotations_json: str | None = None,
    stack_vars: list[dict] | None = None,
    cache_dir: Path | None = None,
    quality: str = "normal",
    provider: str = "auto",
) -> dict[str, Any]:
    """Décompile une fonction. decompiler='' → chaîne auto Ghidra → RetDec → angr."""
    normalized_quality = _normalize_quality(quality)
    provider = _normalize_provider(provider)
    resolved_addr, resolved_func_name = _resolve_function_target(binary_path, addr, func_name)
    addr = resolved_addr or addr
    func_name = resolved_func_name or func_name
    base: dict[str, Any] = {"addr": addr, "code": "", "error": None, "quality": normalized_quality}
    if not Path(binary_path).exists():
        base["error"] = f"Fichier introuvable : {binary_path}"
        return base
    ann_map, annotation_comments = _load_annotations_payload(annotations_json)
    typed_struct_map, typed_struct_comments, typed_struct_note_catalog = _load_typed_struct_annotation_payload(binary_path)
    for addr_norm, label in typed_struct_map.items():
        ann_map.setdefault(addr_norm, label)
    for addr_norm, comment in typed_struct_comments.items():
        annotation_comments.setdefault(addr_norm, comment)

    # Stack vars depuis stack_frame (graceful degradation si capstone/lief absent)
    stack_frame_data: dict[str, Any] | None = None
    if stack_vars is None:
        try:
            from backends.static.stack_frame import analyse_stack_frame
            func_addr = int(addr, 16) if addr.startswith("0x") else int(addr, 10)
            sf = analyse_stack_frame(binary_path, func_addr)
            stack_frame_data = _stack_frame_payload(sf, None)
            stack_vars = sf.get("vars", []) + sf.get("args", [])
        except Exception as e:
            _log.debug("stack_frame unavailable for %s at %s: %s", binary_path, addr, e)
            stack_vars = []
    else:
        stack_frame_data = _stack_frame_payload(None, stack_vars)

    _cdir = cache_dir if cache_dir is not None else _DEFAULT_CACHE_DIR
    _key = _cache_key(
        binary_path,
        addr,
        func_name=func_name,
        decompiler=decompiler,
        annotations_json=annotations_json,
        stack_signature=_stack_signature(stack_frame_data, stack_vars),
        typed_structs_signature=typed_struct_signature(binary_path),
        quality=normalized_quality,
    )
    cached = _read_cache(_key, _cdir)
    if cached is not None:
        return cached

    expected_calls = _extract_reachable_call_names(binary_path, addr)

    def _postprocess(result: dict) -> dict:
        raw_code = result.get("code", "") or ""
        if result.get("code") and (ann_map or stack_vars):
            result["code"] = _postprocess_code(
                raw_code,
                ann_map,
                stack_vars,
                binary_path=binary_path,
                addr=addr,
                decompiler=str(result.get("decompiler") or decompiler or ""),
            )
        elif result.get("code") and str(result.get("decompiler") or decompiler or "") == "r2pdc":
            result["code"] = _postprocess_code(
                raw_code,
                ann_map,
                stack_vars,
                binary_path=binary_path,
                addr=addr,
                decompiler="r2pdc",
            )
        notes = _collect_annotation_notes(raw_code, ann_map, annotation_comments)
        if notes:
            result["annotations"] = notes
        typed_struct_notes = _collect_typed_struct_notes(raw_code, typed_struct_note_catalog)
        if typed_struct_notes:
            result["typed_structs"] = typed_struct_notes
        if stack_frame_data:
            result["stack_frame"] = stack_frame_data
        result["quality"] = normalized_quality
        return result

    def _scored_attempt(result: dict) -> dict:
        processed = _postprocess(dict(result))
        scored = _score_decompile_code(
            processed.get("code", "") or "",
            str(processed.get("decompiler") or ""),
            expected_calls=expected_calls,
            quality=normalized_quality,
        )
        processed["selected_score"] = scored["score"]
        processed["selected_metrics"] = scored["metrics"]
        return processed

    def _postprocess_and_cache(result: dict) -> dict:
        out = _postprocess(result)
        if not out.get("error"):
            _write_cache(_key, _cdir, out)
        return out

    decompiler = _normalize_decompiler_id(decompiler)

    def _run_function_candidate(candidate: str) -> dict[str, Any]:
        if candidate in _load_custom_decompilers():
            if provider == "docker":
                return _run_custom_decompiler_in_docker(
                    candidate,
                    binary_path,
                    addr=addr,
                    func_name=func_name,
                    full=False,
                )
            return _run_custom_decompiler(
                candidate,
                binary_path,
                addr=addr,
                func_name=func_name,
                full=False,
            )
        return _run_builtin_function_decompiler(
            candidate,
            binary_path,
            addr,
            func_name=func_name,
            provider=provider,
            quality=normalized_quality,
        )

    # Dispatch explicite si décompilateur spécifié
    if decompiler and decompiler not in _BUILTIN_DECOMPILERS:
        explicit = _run_function_candidate(decompiler)
        if not explicit.get("error") and _is_compare_quality(normalized_quality):
            explicit["quality_details"] = _build_quality_details(
                "explicit",
                _scored_attempt(explicit),
                [_scored_attempt(explicit)],
                lambda attempt, backend: _score_decompile_code(
                    attempt.get("code", ""),
                    backend,
                    expected_calls=expected_calls,
                    quality=normalized_quality,
                ),
            )
        return _postprocess_and_cache(explicit)
    if decompiler == "ghidra":
        explicit = _run_function_candidate("ghidra")
        if not explicit.get("error") and normalized_quality == "max":
            explicit["quality_details"] = _build_quality_details(
                "explicit",
                _scored_attempt(explicit),
                [_scored_attempt(explicit)],
                lambda attempt, backend: _score_decompile_code(
                    attempt.get("code", ""),
                    backend,
                    expected_calls=expected_calls,
                    quality=normalized_quality,
                ),
            )
        return _postprocess_and_cache(explicit)
    if decompiler == "angr":
        explicit = _run_function_candidate("angr")
        if not explicit.get("error") and normalized_quality == "max":
            explicit["quality_details"] = _build_quality_details(
                "explicit",
                _scored_attempt(explicit),
                [_scored_attempt(explicit)],
                lambda attempt, backend: _score_decompile_code(
                    attempt.get("code", ""),
                    backend,
                    expected_calls=expected_calls,
                    quality=normalized_quality,
                ),
            )
        return _postprocess_and_cache(explicit)
    if decompiler == "retdec":
        explicit = _run_function_candidate("retdec")
        if not explicit.get("error") and normalized_quality == "max":
            explicit["quality_details"] = _build_quality_details(
                "explicit",
                _scored_attempt(explicit),
                [_scored_attempt(explicit)],
                lambda attempt, backend: _score_decompile_code(
                    attempt.get("code", ""),
                    backend,
                    expected_calls=expected_calls,
                    quality=normalized_quality,
                ),
            )
        return _postprocess_and_cache(explicit)
    # '' → chaîne auto
    if _is_compare_quality(normalized_quality):
        attempts: list[dict[str, Any]] = []
        for candidate in _auto_function_decompiler_order(normalized_quality):
            if not _is_decompiler_available(candidate, provider):
                continue
            attempt = _run_function_candidate(candidate)
            attempt.setdefault("decompiler", candidate)
            attempts.append(_scored_attempt(attempt))
        selected = _select_best_function_candidate(
            [
                {
                    **attempt,
                    "_quality_score": _score_decompile_code(
                        attempt.get("code", ""),
                        attempt.get("decompiler", ""),
                        expected_calls=expected_calls,
                        quality=normalized_quality,
                    )["score"],
                }
                for attempt in attempts
            ]
        )
        if selected is not None:
            selected = dict(selected)
            selected["quality_details"] = _build_quality_details(
                "compare_backends",
                selected,
                attempts,
                lambda attempt, backend: _score_decompile_code(
                    attempt.get("code", ""),
                    backend,
                    expected_calls=expected_calls,
                    quality=normalized_quality,
                ),
            )
            return _postprocess_and_cache(selected)
        if attempts:
            last = dict(attempts[-1])
            last["quality_details"] = _build_quality_details(
                "compare_backends",
                None,
                attempts,
                lambda attempt, backend: _score_decompile_code(
                    attempt.get("code", ""),
                    backend,
                    expected_calls=expected_calls,
                    quality=normalized_quality,
                ),
            )
            return _postprocess(last)
        return _postprocess(base)

    if decompiler != "retdec":
        for candidate in _auto_function_decompiler_order(normalized_quality):
            if candidate == "retdec":
                break
            if not _is_decompiler_available(candidate, provider):
                continue
            r = _run_function_candidate(candidate)
            if not r.get("error"):
                return _postprocess_and_cache(r)
            _log.warning("%s failed (%s), fallback", candidate, r.get("error"))
    return _postprocess_and_cache(_run_function_candidate("retdec"))


def decompile_binary(
    binary_path: str,
    arch: str = "x86_64",
    decompiler: str = "",
    quality: str = "normal",
    provider: str = "auto",
) -> dict[str, Any]:
    """Décompile le binaire entier. decompiler='' → chaîne auto Ghidra → RetDec → angr."""
    normalized_quality = _normalize_quality(quality)
    provider = _normalize_provider(provider)
    decompiler = _normalize_decompiler_id(decompiler)
    result: dict[str, Any] = {"functions": [], "error": None, "quality": normalized_quality}
    if not Path(binary_path).exists():
        result["error"] = f"Fichier introuvable : {binary_path}"
        return result

    def _run_binary_candidate(candidate: str) -> dict[str, Any]:
        if candidate in _load_custom_decompilers():
            if provider == "docker":
                return _run_custom_decompiler_in_docker(candidate, binary_path, full=True)
            return _run_custom_decompiler(candidate, binary_path, full=True)
        return _run_builtin_binary_decompiler(
            candidate,
            binary_path,
            provider=provider,
            quality=normalized_quality,
        )

    # Dispatch explicite si décompilateur spécifié
    if decompiler and decompiler not in _BUILTIN_DECOMPILERS:
        out = _run_binary_candidate(decompiler)
        if not out.get("error") and _is_compare_quality(normalized_quality):
            out["quality_details"] = _build_quality_details(
                "explicit",
                out,
                [out],
                lambda attempt, backend: _score_binary_decompile(
                    attempt,
                    backend,
                    quality=normalized_quality,
                ),
            )
        out["quality"] = normalized_quality
        return out
    if decompiler == "ghidra":
        out = _run_binary_candidate("ghidra")
        if not out.get("error") and _is_compare_quality(normalized_quality):
            out["quality_details"] = _build_quality_details(
                "explicit",
                out,
                [out],
                lambda attempt, backend: _score_binary_decompile(
                    attempt,
                    backend,
                    quality=normalized_quality,
                ),
            )
        out["quality"] = normalized_quality
        return out
    if decompiler == "angr":
        out = _run_binary_candidate("angr")
        if not out.get("error") and _is_compare_quality(normalized_quality):
            out["quality_details"] = _build_quality_details(
                "explicit",
                out,
                [out],
                lambda attempt, backend: _score_binary_decompile(
                    attempt,
                    backend,
                    quality=normalized_quality,
                ),
            )
        out["quality"] = normalized_quality
        return out
    if decompiler == "retdec":
        out = _run_binary_candidate("retdec")
        if not out.get("error") and _is_compare_quality(normalized_quality):
            out["quality_details"] = _build_quality_details(
                "explicit",
                out,
                [out],
                lambda attempt, backend: _score_binary_decompile(
                    attempt,
                    backend,
                    quality=normalized_quality,
                ),
            )
        out["quality"] = normalized_quality
        return out
    # 'retdec' ou '' → chaîne auto
    if _is_compare_quality(normalized_quality):
        attempts: list[dict[str, Any]] = []
        for candidate in _auto_binary_decompiler_order(normalized_quality):
            if not _is_decompiler_available(candidate, provider):
                continue
            attempt = _run_binary_candidate(candidate)
            attempt.setdefault("decompiler", candidate)
            attempt["quality"] = normalized_quality
            attempts.append(attempt)
        selected = _select_best_binary_candidate(
            [
                {
                    **attempt,
                    "_quality_score": _score_binary_decompile(
                        attempt,
                        attempt.get("decompiler", ""),
                        quality=normalized_quality,
                    )["score"],
                }
                for attempt in attempts
            ]
        )
        if selected is not None:
            selected = dict(selected)
            selected["quality"] = normalized_quality
            selected["quality_details"] = _build_quality_details(
                "compare_backends",
                selected,
                attempts,
                lambda attempt, backend: _score_binary_decompile(
                    attempt,
                    backend,
                    quality=normalized_quality,
                ),
            )
            return selected
        if attempts:
            last = dict(attempts[-1])
            last["quality"] = normalized_quality
            last["quality_details"] = _build_quality_details(
                "compare_backends",
                None,
                attempts,
                lambda attempt, backend: _score_binary_decompile(
                    attempt,
                    backend,
                    quality=normalized_quality,
                ),
            )
            return last
        return result

    if decompiler != "retdec":
        for candidate in _auto_binary_decompiler_order(normalized_quality):
            if candidate == "retdec":
                break
            if not _is_decompiler_available(candidate, provider):
                continue
            r = _run_binary_candidate(candidate)
            if not r.get("error"):
                r["quality"] = normalized_quality
                return r
            _log.warning("%s binary failed (%s), fallback", candidate, r.get("error"))
    out = _run_binary_candidate("retdec")
    out["quality"] = normalized_quality
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=None)
    parser.add_argument("--addr", default=None)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--func-name", default="")
    parser.add_argument(
        "--decompiler",
        default="",
        help="Backend à utiliser: ghidra, retdec, angr ou ID custom déclaré dans .pile-ou-face/decompilers.json",
    )
    parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "local", "docker"],
        help="auto = local puis Docker, local = outils installés, docker = image dédiée au décompilateur (builtin ou custom)",
    )
    parser.add_argument(
        "--list", action="store_true", help="Lister les décompilateurs disponibles"
    )
    parser.add_argument(
        "--hide-builtin",
        default=None,
        help="Masquer un builtin de la liste (ex: ghidra). L'ajoute à hidden_builtins.",
    )
    parser.add_argument(
        "--restore-builtin",
        default=None,
        help="Restaurer un builtin masqué (ex: ghidra). Le retire de hidden_builtins.",
    )
    parser.add_argument(
        "--annotations-json",
        default=None,
        help="Chemin JSON d'annotations {addr: {name, comment}} pour substitution dans le pseudo-C",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Dossier cache (défaut : .pile-ou-face/decompile_cache/)",
    )
    parser.add_argument(
        "--quality",
        default="normal",
        choices=["normal", "max", "precision"],
        help="normal = rapide, precision = fidélité au binaire d'abord, max = alias de compatibilité vers precision",
    )
    args = parser.parse_args()
    if args.list:
        print(json.dumps(list_available_decompilers(provider=args.provider), indent=2))
        sys.exit(0)
    if args.hide_builtin:
        bid = _normalize_decompiler_id(args.hide_builtin)
        if bid not in _BUILTIN_DECOMPILERS:
            print(json.dumps({"error": f"'{bid}' n'est pas un builtin connu"}))
            sys.exit(1)
        if bid in _CURATED_BUILTIN_DECOMPILERS:
            print(json.dumps({"error": f"'{bid}' fait partie du trio decompilateur expose et ne peut pas etre masque"}))
            sys.exit(1)
        hidden = _load_hidden_builtins()
        if bid not in hidden:
            hidden.append(bid)
            _save_hidden_builtins(hidden)
        print(json.dumps({"ok": True, "hidden_builtins": hidden}))
        sys.exit(0)
    if args.restore_builtin:
        bid = _normalize_decompiler_id(args.restore_builtin)
        hidden = _load_hidden_builtins()
        if bid in hidden:
            hidden.remove(bid)
            _save_hidden_builtins(hidden)
        print(json.dumps({"ok": True, "hidden_builtins": hidden}))
        sys.exit(0)
    if not args.binary:
        parser.error("--binary est requis")
    if args.full or not args.addr:
        print(
            json.dumps(
                decompile_binary(
                    args.binary,
                    decompiler=args.decompiler,
                    quality=args.quality,
                    provider=args.provider,
                ),
                indent=2,
            )
        )
    else:
        ann_json = getattr(args, "annotations_json", None)
        print(
            json.dumps(
                decompile_function(
                    args.binary,
                    args.addr,
                    func_name=args.func_name,
                    decompiler=args.decompiler,
                    annotations_json=ann_json,
                    cache_dir=Path(args.cache_dir) if args.cache_dir else None,
                    quality=args.quality,
                    provider=args.provider,
                ),
                indent=2,
            )
        )
