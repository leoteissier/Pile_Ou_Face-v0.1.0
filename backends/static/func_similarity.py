"""Function similarity by MinHash over opcode shingles.

Supports both:
- binary-to-binary comparison
- workspace-local indexed reference database
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

DB_REL_PATH = Path(".pile-ou-face") / "function_similarity.pfdb"
BUNDLED_DB_PATH = Path(__file__).resolve().parent / "data" / "function_similarity_refs.json"


# -- MinHash -----------------------------------------------------------------

_NUM_HASHES = 128


def _hash_shingle(shingle: str, seed: int) -> int:
    digest = hashlib.md5(f"{seed}:{shingle}".encode()).digest()
    return int.from_bytes(digest[:8], "little")


def minhash(shingles: set[str]) -> list[int]:
    if not shingles:
        return [0xFFFFFFFFFFFFFFFF] * _NUM_HASHES
    signature = []
    for seed in range(_NUM_HASHES):
        signature.append(min(_hash_shingle(shingle, seed) for shingle in shingles))
    return signature


def jaccard_estimate(sig_a: list[int], sig_b: list[int]) -> float:
    if not sig_a or not sig_b:
        return 0.0
    matches = sum(1 for left, right in zip(sig_a, sig_b) if left == right)
    return matches / len(sig_a)


# -- Disassembly helpers -----------------------------------------------------

def _mnemonic(text: str) -> str:
    parts = text.strip().split()
    for part in parts:
        try:
            int(part, 16)
        except ValueError:
            return part.lower()
    return ""


def _opcodes_from_blocks(blocks: list[dict]) -> list[str]:
    opcodes = []
    for block in blocks:
        for line in block.get("lines", []):
            mnemonic = _mnemonic(line.get("text", ""))
            if mnemonic and mnemonic not in ("db", "dw", "dd", "dq"):
                opcodes.append(mnemonic)
    return opcodes


def _shingles(opcodes: list[str], n: int = 3) -> set[str]:
    if len(opcodes) < n:
        return {" ".join(opcodes)} if opcodes else set()
    return {" ".join(opcodes[idx : idx + n]) for idx in range(len(opcodes) - n + 1)}


def _load_disasm(binary_path: str) -> list[dict]:
    from backends.static.cache import DisasmCache, default_cache_path
    from backends.static.disasm import disassemble_with_capstone

    cache_path = None
    try:
        cache_path = default_cache_path(binary_path)
        with DisasmCache(cache_path) as cache:
            cached = cache.get_disasm(binary_path)
            if cached:
                _, lines = cached
                return lines
    except Exception:
        cache_path = None

    lines = disassemble_with_capstone(binary_path) or []
    if lines and cache_path:
        try:
            with DisasmCache(cache_path) as cache:
                cache.save_disasm(binary_path, lines)
        except Exception:
            pass
    return lines


def _load_cfg(binary_path: str, lines: list[dict]) -> dict:
    """Charge le CFG depuis le cache ou le calcule et le met en cache."""
    from backends.static.cache import DisasmCache, default_cache_path
    from backends.static.cfg import build_cfg

    try:
        cache_path = default_cache_path(binary_path)
        with DisasmCache(cache_path) as cache:
            cached = cache.get_cfg(binary_path)
            if cached:
                return cached
        cfg = build_cfg(lines, binary_path=binary_path)
        with DisasmCache(cache_path) as cache:
            cache.save_cfg(binary_path, cfg)
        return cfg
    except Exception:
        return build_cfg(lines, binary_path=binary_path)


def _load_function_symbols(binary_path: str, lines: list[dict]) -> list[dict]:
    """Charge les symboles de fonctions depuis le cache ou les calcule."""
    from backends.static.cache import DisasmCache, default_cache_path
    from backends.static.symbols import extract_symbols

    try:
        cache_path = default_cache_path(binary_path)
        with DisasmCache(cache_path) as cache:
            cached = cache.get_functions(binary_path)
            if cached:
                return cached
    except Exception:
        pass

    symbols = extract_symbols(binary_path, defined_only=False)
    function_symbols = [s for s in symbols if s.get("type") in ("T", "t", "F", "f", "W", "w")]

    if not function_symbols:
        from backends.static.discover_functions import discover_functions

        discovered = discover_functions(lines, known_addrs=set()) or []
        function_symbols = [
            {"addr": func["addr"], "name": func.get("label") or f"sub_{func['addr'][2:]}"}
            for func in discovered
        ]

    return function_symbols


def index_binary(binary_path: str) -> list[dict]:
    lines = _load_disasm(binary_path)
    if not lines:
        return []

    function_symbols = _load_function_symbols(binary_path, lines)
    if not function_symbols:
        return []

    full_cfg = _load_cfg(binary_path, lines)
    block_by_addr = {block["addr"]: block for block in full_cfg.get("blocks", [])}

    from backends.shared.utils import normalize_addr
    from collections import defaultdict

    non_call_successors = defaultdict(list)
    for edge in full_cfg.get("edges", []):
        if edge["type"] != "call":
            non_call_successors[edge["from"]].append(edge["to"])

    def collect_function_blocks(start_addr: str) -> list[dict]:
        normalized = normalize_addr(start_addr)
        if normalized not in block_by_addr:
            return []
        visited = set()
        queue = [normalized]
        blocks = []
        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)
            if current in block_by_addr:
                blocks.append(block_by_addr[current])
                queue.extend(non_call_successors.get(current, []))
        return blocks

    index = []
    for symbol in function_symbols:
        addr = symbol.get("addr", "0x0")
        name = symbol.get("name", f"sub_{addr[2:]}")
        blocks = collect_function_blocks(addr)
        opcodes = _opcodes_from_blocks(blocks)
        if len(opcodes) < 4:
            continue
        index.append(
            {
                "addr": addr,
                "name": name,
                "sig": minhash(_shingles(opcodes)),
                "opcode_count": len(opcodes),
            }
        )
    return index


# -- Reference database ------------------------------------------------------

def get_reference_db_path(workspace_root: str | None = None) -> Path:
    root = Path(workspace_root or Path.cwd())
    return root / DB_REL_PATH


def get_bundled_reference_db_path() -> Path:
    return BUNDLED_DB_PATH


def _sha256_file(binary_path: str) -> str:
    digest = hashlib.sha256()
    with open(binary_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_reference_db(workspace_root: str | None = None) -> dict:
    db_path = get_reference_db_path(workspace_root)
    if not db_path.is_file():
        return {"references": []}
    try:
        payload = json.loads(db_path.read_text(encoding="utf-8"))
    except Exception:
        return {"references": []}
    references = payload.get("references")
    if not isinstance(references, list):
        references = []
    return {"references": references}


def load_bundled_reference_db() -> dict:
    db_path = get_bundled_reference_db_path()
    if not db_path.is_file():
        return {"references": [], "pack": {}}
    try:
        payload = json.loads(db_path.read_text(encoding="utf-8"))
    except Exception:
        return {"references": [], "pack": {}}
    references = payload.get("references")
    pack = payload.get("pack") if isinstance(payload, dict) else {}
    if not isinstance(references, list):
        references = []
    if not isinstance(pack, dict):
        pack = {}
    return {"references": references, "pack": pack}


def save_reference_db(payload: dict, workspace_root: str | None = None) -> Path:
    db_path = get_reference_db_path(workspace_root)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return db_path


def _summarize_reference_entries(references: list[dict], *, source: str, pack_name: str = "") -> tuple[list[dict], int]:
    summary = []
    for ref in references:
        ref_id = str(ref.get("sha256") or "")
        summary.append(
            {
                "id": ref_id,
                "label": ref.get("label") or ref.get("name") or "",
                "name": ref.get("name") or "",
                "path": ref.get("path") or "",
                "sha256": ref.get("sha256") or "",
                "function_count": int(ref.get("function_count") or len(ref.get("functions") or [])),
                "indexed_at": int(ref.get("indexed_at") or 0),
                "source": source,
                "pack": ref.get("pack") or pack_name or "",
                "family": ref.get("family") or "",
                "editable": source == "workspace" and bool(ref_id),
                "deletable": source == "workspace" and bool(ref_id),
            }
        )
    summary.sort(key=lambda item: (item["label"] or item["name"]).lower())
    function_count = sum(item["function_count"] for item in summary)
    return summary, function_count


def list_reference_db(workspace_root: str | None = None, include_bundled: bool = True) -> dict:
    db = load_reference_db(workspace_root)
    local_refs = db.get("references", [])
    local_summary, local_function_count = _summarize_reference_entries(local_refs, source="workspace")
    bundled_summary: list[dict] = []
    bundled_function_count = 0
    pack = {}
    if include_bundled:
        bundled_db = load_bundled_reference_db()
        pack = bundled_db.get("pack") or {}
        bundled_summary, bundled_function_count = _summarize_reference_entries(
            bundled_db.get("references", []),
            source="bundled",
            pack_name=str(pack.get("name") or ""),
        )
    summary = [*local_summary, *bundled_summary]
    function_count = local_function_count + bundled_function_count
    return {
        "references": summary,
        "workspace_references": local_summary,
        "bundled_references": bundled_summary,
        "pack": pack,
        "stats": {
            "reference_binaries": len(summary),
            "reference_functions": function_count,
            "workspace_binaries": len(local_summary),
            "workspace_functions": local_function_count,
            "bundled_binaries": len(bundled_summary),
            "bundled_functions": bundled_function_count,
        },
        "error": None,
    }


def clear_reference_db(workspace_root: str | None = None) -> dict:
    save_reference_db({"references": []}, workspace_root)
    return list_reference_db(workspace_root)


def remove_reference_entry(reference_id: str, workspace_root: str | None = None) -> dict:
    ref_id = str(reference_id or "").strip().lower()
    if not ref_id:
        return {"error": "Identifiant de référence manquant", "references": []}
    db = load_reference_db(workspace_root)
    references = db.get("references", [])
    kept = [ref for ref in references if str(ref.get("sha256") or "").lower() != ref_id]
    if len(kept) == len(references):
        return {"error": "Référence introuvable dans la base locale", "references": []}
    save_reference_db({"references": kept}, workspace_root)
    listing = list_reference_db(workspace_root)
    listing["removed"] = {"id": ref_id}
    return listing


def update_reference_label(reference_id: str, label: str, workspace_root: str | None = None) -> dict:
    ref_id = str(reference_id or "").strip().lower()
    new_label = str(label or "").strip()
    if not ref_id:
        return {"error": "Identifiant de référence manquant", "references": []}
    if not new_label:
        return {"error": "Le label ne peut pas être vide", "references": []}
    db = load_reference_db(workspace_root)
    references = db.get("references", [])
    updated = None
    for ref in references:
        if str(ref.get("sha256") or "").lower() != ref_id:
            continue
        ref["label"] = new_label
        updated = {
            "id": ref_id,
            "label": new_label,
            "name": ref.get("name") or "",
            "path": ref.get("path") or "",
        }
        break
    if not updated:
        return {"error": "Référence introuvable dans la base locale", "references": []}
    save_reference_db({"references": references}, workspace_root)
    listing = list_reference_db(workspace_root)
    listing["updated"] = updated
    return listing


def index_reference_binary(reference_path: str, label: str | None = None, workspace_root: str | None = None) -> dict:
    ref_path = Path(reference_path)
    if not ref_path.exists():
        return {"error": f"Fichier introuvable : {reference_path}", "references": []}

    functions = index_binary(str(ref_path))
    if not functions:
        return {"error": "Aucune fonction indexable trouvée dans le binaire de référence", "references": []}

    sha256 = _sha256_file(str(ref_path))
    db = load_reference_db(workspace_root)
    references = [ref for ref in db.get("references", []) if ref.get("sha256") != sha256]
    entry = {
        "label": label or ref_path.name,
        "name": ref_path.name,
        "path": str(ref_path.resolve()),
        "sha256": sha256,
        "indexed_at": int(time.time()),
        "function_count": len(functions),
        "functions": functions,
    }
    references.append(entry)
    save_reference_db({"references": references}, workspace_root)
    listing = list_reference_db(workspace_root)
    listing["indexed"] = {
        "label": entry["label"],
        "name": entry["name"],
        "path": entry["path"],
        "function_count": entry["function_count"],
        "sha256": sha256,
    }
    return listing


# -- Comparison --------------------------------------------------------------

def _compare_indexes(
    target_index: list[dict],
    reference_entries: list[dict],
    threshold: float,
    top: int,
) -> list[dict]:
    matches = []
    top = max(1, int(top or 1))
    for target_func in target_index:
        scored = []
        for ref in reference_entries:
            score = jaccard_estimate(target_func["sig"], ref["sig"])
            if score < threshold:
                continue
            scored.append(
                {
                    "addr": target_func["addr"],
                    "name": target_func["name"],
                    "match_name": ref["name"],
                    "match_addr": ref["addr"],
                    "score": round(score, 3),
                    "ref_binary": ref.get("ref_binary") or "?",
                    "ref_label": ref.get("ref_label") or ref.get("ref_binary") or "?",
                    "ref_path": ref.get("ref_path") or "",
                    "ref_source": ref.get("ref_source") or "",
                    "ref_pack": ref.get("ref_pack") or "",
                    "ref_family": ref.get("ref_family") or "",
                    "opcode_count": target_func["opcode_count"],
                }
            )
        scored.sort(key=lambda item: item["score"], reverse=True)
        matches.extend(scored[:top])
    matches.sort(key=lambda item: (item["score"], item["name"]), reverse=True)
    return matches


def compare(target_path: str, reference_path: str, threshold: float = 0.4, top: int = 1) -> dict:
    target_index = index_binary(target_path)
    if not target_index:
        return {"matches": [], "stats": {}, "error": "Aucune fonction trouvée dans le binaire cible"}

    ref_index = index_binary(reference_path)
    if not ref_index:
        return {"matches": [], "stats": {}, "error": "Aucune fonction trouvée dans le binaire de référence"}

    ref_name = Path(reference_path).name
    reference_entries = [
        {
            **func,
            "ref_binary": ref_name,
            "ref_label": ref_name,
            "ref_path": str(Path(reference_path).resolve()),
        }
        for func in ref_index
    ]
    matches = _compare_indexes(target_index, reference_entries, threshold, top)
    return {
        "matches": matches,
        "stats": {
            "target_functions": len(target_index),
            "ref_functions": len(ref_index),
            "matches_found": len(matches),
            "threshold": threshold,
            "reference_binaries": 1,
        },
        "error": None,
    }


def _flatten_reference_entries(references: list[dict], *, default_source: str, default_pack: str = "") -> list[dict]:
    flattened = []
    for ref in references:
        label = ref.get("label") or ref.get("name") or "reference"
        ref_binary = ref.get("name") or label
        ref_path = ref.get("path") or ""
        ref_source = ref.get("source") or default_source
        ref_pack = ref.get("pack") or default_pack or ""
        ref_family = ref.get("family") or ""
        for func in ref.get("functions") or []:
            flattened.append(
                {
                    **func,
                    "ref_binary": ref_binary,
                    "ref_label": label,
                    "ref_path": ref_path,
                    "ref_source": ref_source,
                    "ref_pack": ref_pack,
                    "ref_family": ref_family,
                }
            )
    return flattened


def compare_against_reference_db(
    target_path: str,
    threshold: float = 0.4,
    top: int = 1,
    workspace_root: str | None = None,
    include_bundled: bool = True,
) -> dict:
    db = load_reference_db(workspace_root)
    references = db.get("references", [])
    bundled_db = load_bundled_reference_db() if include_bundled else {"references": [], "pack": {}}
    bundled_refs = bundled_db.get("references", [])
    all_references = [*references, *bundled_refs]
    if not all_references:
        return {"matches": [], "stats": {}, "error": "La base de similarité est vide"}

    target_index = index_binary(target_path)
    if not target_index:
        return {"matches": [], "stats": {}, "error": "Aucune fonction trouvée dans le binaire cible"}

    reference_entries = _flatten_reference_entries(references, default_source="workspace")
    reference_entries.extend(
        _flatten_reference_entries(
            bundled_refs,
            default_source="bundled",
            default_pack=str((bundled_db.get("pack") or {}).get("name") or ""),
        )
    )

    matches = _compare_indexes(target_index, reference_entries, threshold, top)
    return {
        "matches": matches,
        "stats": {
            "target_functions": len(target_index),
            "ref_functions": len(reference_entries),
            "matches_found": len(matches),
            "threshold": threshold,
            "reference_binaries": len(all_references),
            "workspace_binaries": len(references),
            "bundled_binaries": len(bundled_refs),
        },
        "references": [
            {
                "label": ref.get("label") or ref.get("name") or "",
                "name": ref.get("name") or "",
                "function_count": int(ref.get("function_count") or len(ref.get("functions") or [])),
                "path": ref.get("path") or "",
                "source": ref.get("source") or ("bundled" if ref in bundled_refs else "workspace"),
                "pack": ref.get("pack") or str((bundled_db.get("pack") or {}).get("name") or ""),
                "family": ref.get("family") or "",
            }
            for ref in all_references
        ],
        "error": None,
    }


# -- CLI ---------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Function similarity by MinHash")
    parser.add_argument("--binary", help="Target binary")
    parser.add_argument("--reference", help="Reference binary")
    parser.add_argument("--threshold", type=float, default=0.4, help="Similarity threshold (0-1)")
    parser.add_argument("--top", type=int, default=1, help="Maximum matches per target function")
    parser.add_argument("--index-reference", help="Add a binary to the local similarity DB")
    parser.add_argument("--remove-reference", help="Remove a reference from the local similarity DB by sha256")
    parser.add_argument("--update-reference-label", help="Update a local reference label by sha256")
    parser.add_argument("--label", help="Optional label for the indexed reference binary")
    parser.add_argument("--search-db", action="store_true", help="Search the local similarity DB")
    parser.add_argument("--list-db", action="store_true", help="List indexed reference binaries")
    parser.add_argument("--clear-db", action="store_true", help="Clear the local similarity DB")
    parser.add_argument("--no-bundled-db", action="store_true", help="Ignore the bundled starter reference DB")
    parser.add_argument("--workspace-root", help="Workspace root used for the local similarity DB")
    args = parser.parse_args()

    if args.list_db:
        result = list_reference_db(args.workspace_root, include_bundled=not args.no_bundled_db)
        print(json.dumps(result, indent=2))
        return 0
    if args.clear_db:
        result = clear_reference_db(args.workspace_root)
        print(json.dumps(result, indent=2))
        return 0
    if args.remove_reference:
        result = remove_reference_entry(args.remove_reference, args.workspace_root)
        print(json.dumps(result, indent=2))
        return 0
    if args.update_reference_label:
        if not args.label:
            print(json.dumps({"error": "--label est requis avec --update-reference-label"}))
            return 1
        result = update_reference_label(args.update_reference_label, args.label, args.workspace_root)
        print(json.dumps(result, indent=2))
        return 0
    if args.index_reference:
        result = index_reference_binary(args.index_reference, args.label, args.workspace_root)
        print(json.dumps(result, indent=2))
        return 0
    if args.search_db:
        if not args.binary:
            print(json.dumps({"error": "--binary est requis avec --search-db"}))
            return 1
        if not Path(args.binary).exists():
            print(json.dumps({"error": f"Fichier introuvable : {args.binary}"}))
            return 1
        result = compare_against_reference_db(
            args.binary,
            args.threshold,
            args.top,
            args.workspace_root,
            include_bundled=not args.no_bundled_db,
        )
        print(json.dumps(result, indent=2))
        return 0

    if not args.binary or not args.reference:
        print(json.dumps({"error": "--binary et --reference sont requis"}))
        return 1
    if not Path(args.binary).exists():
        print(json.dumps({"error": f"Fichier introuvable : {args.binary}"}))
        return 1
    if not Path(args.reference).exists():
        print(json.dumps({"error": f"Fichier introuvable : {args.reference}"}))
        return 1

    result = compare(args.binary, args.reference, args.threshold, args.top)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
