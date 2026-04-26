"""Déobfuscation de strings par analyse statique (XOR, ROT, Base64, stackstrings).

CLI:
  python string_deobfuscate.py --binary <path>

Output JSON: [{addr, raw_hex, decoded, method, confidence}]
"""

from __future__ import annotations
import argparse, base64, json, re, string
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger
from backends.shared.utils import build_offset_to_vaddr as _build_offset_to_vaddr

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:  # pragma: no cover - optional dependency
    Cipher = algorithms = modes = None

_log = get_logger(__name__)
_MIN_LEN = 4
_PRINTABLE = set(string.printable)

# English letter relative frequencies (a-z).
_EN_FREQ: dict[str, float] = {
    "e": 0.1270,
    "t": 0.0906,
    "a": 0.0817,
    "o": 0.0751,
    "i": 0.0697,
    "n": 0.0675,
    "s": 0.0633,
    "h": 0.0609,
    "r": 0.0599,
    "d": 0.0425,
    "l": 0.0403,
    "c": 0.0278,
    "u": 0.0276,
    "m": 0.0241,
    "w": 0.0236,
    "f": 0.0223,
    "g": 0.0202,
    "y": 0.0197,
    "p": 0.0193,
    "b": 0.0149,
    "v": 0.0098,
    "k": 0.0077,
    "j": 0.0015,
    "x": 0.0015,
    "q": 0.0010,
    "z": 0.0007,
}

# Minimal common-word bonus set (most frequent English words and greetings).
_COMMON_WORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "are",
        "but",
        "not",
        "you",
        "all",
        "can",
        "her",
        "was",
        "one",
        "our",
        "out",
        "day",
        "get",
        "has",
        "him",
        "his",
        "how",
        "its",
        "may",
        "new",
        "now",
        "old",
        "see",
        "two",
        "who",
        "did",
        "let",
        "put",
        "say",
        "she",
        "too",
        "use",
        # common greetings / short words frequently used in test data
        "hello",
        "world",
        "test",
        "flag",
        "pass",
        "fail",
        "open",
        "read",
        "file",
        "path",
        "host",
        "port",
        "user",
        "data",
        "code",
        "exec",
        "root",
        "home",
        "help",
        "name",
        "type",
        "list",
        "load",
        "find",
    }
)

# Base64 patterns — standard and URL-safe variants
_B64_RE = re.compile(
    rb"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
_B64URL_RE = re.compile(
    rb"(?:[A-Za-z0-9\-_]{4}){2,}(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?"
)
_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{4,64}")
_KEY_TOKEN_RE = re.compile(rb"[A-Za-z0-9_./+-]{4,64}")

# Stackstring patterns: series of single-byte MOV to stack slots (x86-64)
# mov byte ptr [rbp-N], imm8   →  C6 45 ?? ??
# mov byte ptr [rsp+N], imm8   →  C6 44 24 ?? ??
_STACKSTR_RBP = re.compile(rb"(?:\xC6\x45[\x00-\xff][\x20-\x7e]){4,}")
_STACKSTR_RSP = re.compile(rb"(?:\xC6\x44\x24[\x00-\xff][\x20-\x7e]){4,}")

# ARM64: movz wN, #char (char 0x20-0x7E), little-endian 4-byte instruction.
# Encoding: byte3=0x52, byte2=0x80, byte1=char>>3 ∈ [4,15], byte0=any.
# char = (byte1 << 3) | (byte0 >> 5)
# Compilers interleave ldr/strb; we collect all movz positions and group
# nearby ones (within _ARM64_GAP bytes) into candidate stackstrings.
_MOVZ_ARM64 = re.compile(rb"[\x00-\xff][\x04-\x0f]\x80\x52")


def _is_printable_string(s: str, min_len: int = _MIN_LEN) -> bool:
    if len(s) < min_len:
        return False
    return all(c in _PRINTABLE for c in s)


_VOWELS = frozenset("aeiou")


def _has_diversity(s: str, min_unique: int = 4) -> bool:
    """Vérifie que la string ressemble à du texte lisible.

    Critères cumulatifs :
    1. Au moins min_unique caractères distincts
    2. Aucun caractère ne dépasse 35 % des lettres (pas de "EEEEEE")
    3. Au moins 12 % de voyelles parmi les lettres (pas de "TTRQTW")
    4. Caractères spéciaux (non alphanum/espace) ≤ 20 % du total
    """
    if len(s) < min_unique:
        return True  # Trop courte pour appliquer le critère

    lower = s.lower()
    unique = set(lower)

    # 1. Diversité minimale
    if len(unique) < min_unique:
        return False

    alpha_count = sum(c.isalpha() for c in lower)
    if alpha_count == 0:
        return True

    # 2. Pas de caractère dominant (≤35 %)
    max_freq = max(lower.count(c) for c in unique if c.isalpha())
    if (max_freq / alpha_count) > 0.35:
        return False

    # 3. Ratio de voyelles suffisant (≥12 %)
    vowel_count = sum(c in _VOWELS for c in lower if c.isalpha())
    if (vowel_count / alpha_count) < 0.12:
        return False

    # 4. Pas trop de caractères spéciaux
    special_count = sum(not c.isalnum() and c != " " for c in s)
    if (special_count / len(s)) > 0.20:
        return False

    return True


def _english_score(s: str) -> float:
    """Score how English-like a string is.

    Uses letter-frequency dot-product plus a word-bonus for known common words.
    Higher = more English-like.
    """
    if not s:
        return 0.0
    lower = s.lower()
    # Letter frequency score
    freq_score = sum(_EN_FREQ.get(c, 0.0) for c in lower if c.isalpha())
    # Bonus for non-printable chars (heavy penalty)
    penalty = sum(1 for c in s if c not in _PRINTABLE) * 50.0
    # Word-level bonus: sum over every space-separated token that is a known word
    word_bonus = sum(10.0 for token in lower.split() if token in _COMMON_WORDS)
    # Whole-string match bonus (for short strings without spaces)
    if lower.strip() in _COMMON_WORDS:
        word_bonus += 20.0
    return freq_score + word_bonus - penalty


def _try_xor_single(data: bytes) -> tuple[str, int] | None:
    """Tente XOR avec chaque byte 0x01-0xFF.

    Retourne (decoded, key) pour la clé qui donne le score anglais le plus élevé,
    ou None si aucune clé ne produit une chaîne imprimable et diversifiée.
    """
    best: tuple[float, str, int] | None = None
    for key in range(1, 256):
        decoded_bytes = bytes(b ^ key for b in data)
        try:
            decoded = decoded_bytes.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError):
            continue
        if not _is_printable_string(decoded):
            continue
        if not _has_diversity(decoded):
            continue
        score = _english_score(decoded)
        if best is None or score > best[0]:
            best = (score, decoded, key)
    if best is None or best[0] <= len(data) * 0.15:
        return None
    _, decoded, key = best
    return decoded, key


def _try_xor_multi(data: bytes, max_key_len: int = 16) -> tuple[str, bytes] | None:
    """Tente XOR avec une clé de 2 à max_key_len bytes.

    Pour chaque longueur de clé candidate, détermine le meilleur byte par position
    via analyse de fréquences, puis évalue le résultat global.

    Retourne (decoded, key_bytes) ou None.
    """
    if len(data) < 8:
        return None

    best_overall: tuple[float, str, bytes] | None = None

    for key_len in range(2, min(max_key_len + 1, len(data) // 2 + 1)):
        key = bytearray()
        for pos in range(key_len):
            # Bytes at this key position
            slice_bytes = bytes(data[i] for i in range(pos, len(data), key_len))
            best_byte = 0
            best_score = -float("inf")
            for k in range(256):
                decoded_slice = bytes(b ^ k for b in slice_bytes)
                try:
                    text = decoded_slice.decode("ascii", errors="strict")
                except (UnicodeDecodeError, ValueError):
                    continue
                score = _english_score(text)
                if score > best_score:
                    best_score = score
                    best_byte = k
            key.append(best_byte)

        # Decrypt the full region with this key
        decrypted = bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
        try:
            decoded = decrypted.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError):
            continue

        if _is_printable_string(decoded) and _has_diversity(decoded):
            score = _english_score(decoded)
            if best_overall is None or score > best_overall[0]:
                best_overall = (score, decoded, bytes(key))

    # Require a meaningful score (> 0.5 per character on average)
    if best_overall is None or best_overall[0] <= len(data) * 0.15:
        return None
    return best_overall[1], best_overall[2]


def _score_candidate_text(decoded: str) -> float:
    """Score un texte décodé pour arbitrer entre plusieurs fenêtres XOR."""
    if not decoded:
        return 0.0
    return _english_score(decoded) / len(decoded)


def _score_key_candidate(key: bytes) -> float:
    if not key:
        return 0.0
    unique = len(set(key))
    ascii_bonus = sum(1 for b in key if 0x30 <= b <= 0x7A) / len(key)
    return unique + ascii_bonus


def _looks_like_key_material(key: bytes, min_len: int = 4, max_len: int = 32) -> bool:
    if not (min_len <= len(key) <= max_len):
        return False
    if len(set(key)) < 3:
        return False
    max_repeat = max(key.count(b) for b in set(key))
    if (max_repeat / len(key)) > 0.65:
        return False
    return True


def _iter_key_variants(blob: bytes) -> list[tuple[bytes, str]]:
    text = blob.strip()
    variants: list[tuple[bytes, str]] = []
    if text:
        variants.append((text, text.decode("ascii", errors="replace")))
    hex_text = text.decode("ascii", errors="ignore").strip()
    if (
        hex_text
        and len(hex_text) % 2 == 0
        and 8 <= len(hex_text) <= 64
        and re.fullmatch(r"[0-9a-fA-F]+", hex_text)
    ):
        try:
            raw = bytes.fromhex(hex_text)
        except ValueError:
            raw = b""
        if raw:
            variants.append((raw, hex_text.lower()))
    return variants


def _extract_hardcoded_key_candidates(
    data: bytes, *, min_len: int = 4, max_len: int = 32, limit: int = 48
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[int, bytes]] = set()
    for match in _ASCII_RUN_RE.finditer(data):
        blob = match.group(0)
        base_offset = match.start()
        for token in _KEY_TOKEN_RE.finditer(blob):
            token_bytes = token.group(0)
            token_offset = base_offset + token.start()
            for raw_key, display in _iter_key_variants(token_bytes):
                if not _looks_like_key_material(raw_key, min_len=min_len, max_len=max_len):
                    continue
                dedupe_key = (token_offset, raw_key)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                candidates.append(
                    {
                        "offset": token_offset,
                        "span_len": len(token_bytes),
                        "key": raw_key,
                        "display": display if len(display) <= 48 else f"{display[:48]}…",
                        "score": _score_key_candidate(raw_key),
                    }
                )
    candidates.sort(key=lambda entry: (entry["score"], len(entry["key"])), reverse=True)
    return candidates[:limit]


def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    if not key:
        return b""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = 0
    j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out.append(byte ^ k)
    return bytes(out)


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes | None:
    if Cipher is None or algorithms is None or modes is None:
        return None
    if len(key) not in (16, 24, 32) or len(data) == 0 or (len(data) % 16) != 0:
        return None
    try:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except Exception:
        return None


def _strip_pkcs7_padding(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad == 0 or pad > 16 or pad > len(data):
        return data
    if data[-pad:] != bytes([pad]) * pad:
        return data
    return data[:-pad]


def _decode_plaintext_candidate(data: bytes) -> str:
    if not data:
        return ""
    trimmed = _strip_pkcs7_padding(data).replace(b"\x00", b"").strip()
    if len(trimmed) < _MIN_LEN:
        return ""
    for encoding in ("utf-8", "ascii", "latin-1"):
        try:
            decoded = trimmed.decode(encoding, errors="strict")
        except (UnicodeDecodeError, ValueError):
            continue
        if not _is_printable_string(decoded):
            continue
        if not any(ch.isalpha() for ch in decoded):
            continue
        if not _has_diversity(decoded):
            continue
        return decoded
    return ""


def _score_crypto_plaintext(decoded: str) -> float:
    if not decoded:
        return 0.0
    bonus = 0.0
    if any(token in decoded.lower() for token in ("http", "user", "path", "cmd", "key", "host", "flag", "hello", "world")):
        bonus += 0.35
    if any(ch in decoded for ch in " /:\\._-="):
        bonus += 0.15
    return _score_candidate_text(decoded) + bonus


def _crypto_result_rank(result: dict[str, Any]) -> float:
    decoded = str(result.get("decoded", ""))
    base = float(result.get("score", 0.0))
    return base * max(1.0, len(decoded) / 10.0)


def _try_rc4_with_candidate(window: bytes, candidate: dict[str, Any]) -> dict[str, Any] | None:
    decrypted = _rc4_crypt(candidate["key"], window)
    decoded = _decode_plaintext_candidate(decrypted)
    if not decoded:
        return None
    score = _score_crypto_plaintext(decoded)
    if score < 0.22:
        return None
    return {
        "decoded": decoded,
        "method": "RC4",
        "confidence": "medium",
        "score": score,
        "key_display": candidate["display"],
        "key_offset": candidate["offset"],
    }


def _try_aes_with_candidate(window: bytes, candidate: dict[str, Any]) -> dict[str, Any] | None:
    decrypted = _aes_ecb_decrypt(candidate["key"], window)
    if not decrypted:
        return None
    decoded = _decode_plaintext_candidate(decrypted)
    if not decoded:
        return None
    score = _score_crypto_plaintext(decoded)
    if score < 0.22:
        return None
    return {
        "decoded": decoded,
        "method": "AES-ECB",
        "confidence": "low" if Cipher is None else "medium",
        "score": score,
        "key_display": candidate["display"],
        "key_offset": candidate["offset"],
    }


def _window_lengths(min_len: int, max_len: int, *, block: int | None = None) -> list[int]:
    lengths = []
    for length in range(max_len, min_len - 1, -4):
        if block and (length % block) != 0:
            continue
        lengths.append(length)
    return lengths


def _scan_stream_cipher_regions(
    data: bytes,
    offset_map: dict[int, int],
    candidate_keys: list[dict[str, Any]],
    *,
    min_len: int = 12,
    max_len: int = 96,
    search_after: int = 192,
    lookbehind: int = 48,
) -> list[dict[str, Any]]:
    if not candidate_keys:
        return []
    hits: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    rc4_lengths = _window_lengths(max(min_len, 12), max_len)
    aes_lengths = _window_lengths(max(min_len, 16), max_len, block=16)

    for candidate in candidate_keys:
        start = max(0, candidate["offset"] - lookbehind)
        end = min(len(data), candidate["offset"] + candidate["span_len"] + search_after)
        cursor = start
        while cursor <= end - min_len:
            best_hit: dict[str, Any] | None = None
            max_here = min(max_len, end - cursor)

            for length in rc4_lengths:
                if length > max_here:
                    continue
                result = _try_rc4_with_candidate(data[cursor:cursor + length], candidate)
                if result:
                    ranked = {**result, "start": cursor, "length": length, "rank": _crypto_result_rank(result)}
                    if best_hit is None or ranked["rank"] > best_hit["rank"]:
                        best_hit = ranked

            if len(candidate["key"]) in (16, 24, 32):
                for length in aes_lengths:
                    if length > max_here:
                        continue
                    result = _try_aes_with_candidate(data[cursor:cursor + length], candidate)
                    if result:
                        ranked = {**result, "start": cursor, "length": length, "rank": _crypto_result_rank(result)}
                        if best_hit is None or ranked["rank"] > best_hit["rank"]:
                            best_hit = ranked

            if best_hit is None:
                cursor += 1
                continue

            dedupe = (best_hit["start"], best_hit["decoded"], best_hit["method"])
            if dedupe not in seen:
                seen.add(dedupe)
                vaddr = offset_map.get(best_hit["start"], best_hit["start"])
                hits.append(
                    {
                        "addr": hex(vaddr),
                        "raw_hex": data[best_hit["start"]:best_hit["start"] + best_hit["length"]].hex(),
                        "decoded": best_hit["decoded"],
                        "method": best_hit["method"],
                        "confidence": best_hit["confidence"],
                        "key_hint": best_hit["key_display"],
                        "key_addr": hex(offset_map.get(best_hit["key_offset"], best_hit["key_offset"])),
                    }
                )
            cursor += max(best_hit["length"], 1)
    return hits


def _best_xor_candidate(data: bytes) -> dict[str, Any] | None:
    """Retourne le meilleur décodage XOR connu pour une fenêtre candidate."""
    best: dict[str, Any] | None = None

    single = _try_xor_single(data)
    if single:
        decoded, key = single
        best = {
            "decoded": decoded,
            "method": f"XOR-{hex(key)}",
            "confidence": "medium",
            "score": _score_candidate_text(decoded),
        }

    multi = _try_xor_multi(data)
    if multi:
        decoded, key_bytes = multi
        candidate = {
            "decoded": decoded,
            "method": f"XOR-multi-{key_bytes.hex()}",
            "confidence": "medium",
            "score": _score_candidate_text(decoded),
        }
        if best is None or candidate["score"] > best["score"]:
            best = candidate

    return best


def _try_rot(data: bytes) -> tuple[str, int] | None:
    """Tente ROT-N pour N=1..25.

    Retourne (decoded, N) pour la rotation qui donne le score anglais le plus élevé,
    ou None si aucune rotation ne produit une chaîne imprimable.
    """
    try:
        text = data.decode("ascii", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    best: tuple[float, str, int] | None = None
    for n in range(1, 26):
        decoded = "".join(
            (
                chr((ord(c) - 65 + n) % 26 + 65)
                if c.isupper()
                else chr((ord(c) - 97 + n) % 26 + 97) if c.islower() else c
            )
            for c in text
        )
        if _is_printable_string(decoded):
            score = _english_score(decoded)
            if best is None or score > best[0]:
                best = (score, decoded, n)
    if best is None:
        return None
    _, decoded, n = best
    return decoded, n


def _scan_base64(data: bytes, offset_map: dict[int, int]) -> list[dict[str, Any]]:
    """Scanne le binaire pour des strings encodées en Base64 (standard et URL-safe).

    Retourne une liste de résultats décodés avec leur adresse virtuelle (ou offset brut).
    """
    results: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()

    for pattern, variant in [(_B64_RE, "base64"), (_B64URL_RE, "base64url")]:
        for m in pattern.finditer(data):
            blob = m.group(0)
            if len(blob) < 8:
                continue
            offset = m.start()
            if offset in seen_offsets:
                continue
            try:
                if variant == "base64url":
                    # Add padding if needed
                    padded = blob + b"=" * (-len(blob) % 4)
                    decoded_bytes = base64.urlsafe_b64decode(padded)
                else:
                    padded = blob + b"=" * (-len(blob) % 4)
                    decoded_bytes = base64.b64decode(padded)
                # Try UTF-8 decode, strip nulls
                decoded = decoded_bytes.decode("utf-8", errors="replace").replace(
                    "\x00", ""
                )
                if not _is_printable_string(decoded):
                    continue
                # Avoid false positives: require at least one letter in the decoded string
                if not any(c.isalpha() for c in decoded):
                    continue
                seen_offsets.add(offset)
                vaddr = offset_map.get(offset, offset)
                results.append(
                    {
                        "addr": hex(vaddr),
                        "raw_hex": blob.decode("ascii", errors="replace"),
                        "decoded": decoded,
                        "method": variant,
                        "confidence": "high",
                    }
                )
            except Exception:
                continue

    return results


def _scan_stackstrings(data: bytes, offset_map: dict[int, int]) -> list[dict[str, Any]]:
    """Détecte les stackstrings : strings construites octet par octet sur la stack.

    x86-64 : séquences de 'mov byte ptr [rbp-N], imm8' (C6 45 ?? ??)
              ou 'mov byte ptr [rsp+N], imm8' (C6 44 24 ?? ??).
    ARM64   : séquences de 'movz wN, #char ; strb wN, [xM, #off]' (8 ou 12 bytes/char).
              char = (byte1 << 3) | (byte0 >> 5) dans l'instruction movz.
    """
    results: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()

    # ── x86-64 ──────────────────────────────────────────────────────────────
    for pattern, enc_len in [(_STACKSTR_RBP, 4), (_STACKSTR_RSP, 5)]:
        for m in pattern.finditer(data):
            offset = m.start()
            if offset in seen_offsets:
                continue
            blob = m.group(0)
            chars = []
            for i in range(0, len(blob), enc_len):
                imm = blob[i + enc_len - 1]
                if 0x20 <= imm <= 0x7E:
                    chars.append(chr(imm))
            decoded = "".join(chars)
            if not _is_printable_string(decoded):
                continue
            seen_offsets.add(offset)
            vaddr = offset_map.get(offset, offset)
            results.append({
                "addr": hex(vaddr),
                "raw_hex": blob.hex(),
                "decoded": decoded,
                "method": "stackstring",
                "confidence": "medium",
            })

    # ── ARM64 ───────────────────────────────────────────────────────────────
    # Collect all movz wN, #printable positions (char = (b1<<3)|(b0>>5)).
    # Group consecutive movz instructions that are within 16 bytes of each
    # other (allowing for interleaved ldr/strb instructions). Runs of ≥ 4
    # movz form a candidate stackstring.
    _ARM64_GAP = 48  # max bytes between two movz to be in the same string
    movz_hits: list[tuple[int, str]] = []
    for m in _MOVZ_ARM64.finditer(data):
        b0, b1 = m.group(0)[0], m.group(0)[1]
        ch = (b1 << 3) | (b0 >> 5)
        if 0x20 <= ch <= 0x7E:
            movz_hits.append((m.start(), chr(ch)))

    # Group nearby movz into runs
    groups: list[list[tuple[int, str]]] = []
    for pos, ch in movz_hits:
        if groups and pos - groups[-1][-1][0] <= _ARM64_GAP:
            groups[-1].append((pos, ch))
        else:
            groups.append([(pos, ch)])

    for group in groups:
        if len(group) < 4:
            continue
        offset = group[0][0]
        if offset in seen_offsets:
            continue
        decoded = "".join(ch for _, ch in group)
        if not _is_printable_string(decoded):
            continue
        seen_offsets.add(offset)
        vaddr = offset_map.get(offset, offset)
        results.append({
            "addr": hex(vaddr),
            "raw_hex": decoded,  # the string itself as "raw"
            "decoded": decoded,
            "method": "stackstring-arm64",
            "confidence": "medium",
        })

    return results


def _parse_asm_int(value: str) -> int | None:
    raw = str(value or "").strip().lower().lstrip("#")
    if not raw:
        return None
    sign = -1 if raw.startswith("-") else 1
    raw = raw.lstrip("+-")
    try:
        if raw.startswith("0x"):
            return sign * int(raw, 16)
        return sign * int(raw, 10)
    except ValueError:
        return None


def _asm_stack_location(text: str) -> tuple[str, int] | None:
    source = str(text or "").lower()
    bracket = re.search(r"\[([^\]]+)\]", source)
    if bracket:
        inner = bracket.group(1).strip().lower()
        comma_form = re.fullmatch(
            r"([a-z0-9_$%]+)\s*,\s*#?([-+]?(?:0x[0-9a-f]+|\d+))",
            inner,
        )
        if comma_form:
            base = comma_form.group(1).lstrip("$%")
            offset = _parse_asm_int(comma_form.group(2))
            if offset is None:
                return None
            return base, offset
        x86_like = re.fullmatch(
            r"([a-z0-9_$%]+)\s*([-+]\s*(?:0x[0-9a-f]+|\d+))?",
            inner,
        )
        if x86_like:
            base = x86_like.group(1).lstrip("$%")
            offset = _parse_asm_int((x86_like.group(2) or "0").replace(" ", ""))
            if offset is None:
                return None
            return base, offset
        return None
    offset_base = re.search(
        r"([-+]?(?:0x[0-9a-f]+|\d+))\s*\(\s*([a-z0-9_$%]+)\s*\)",
        source,
    )
    if offset_base:
        offset = _parse_asm_int(offset_base.group(1))
        if offset is None:
            return None
        return offset_base.group(2).lstrip("$%"), offset
    return None


def _record_asm_stack_char(
    groups: dict[str, dict[int, str]],
    base: str,
    offset: int,
    value: int,
) -> None:
    if not (0x20 <= value <= 0x7E):
        return
    normalized_base = {"fp": "rbp", "x29": "fp", "s0": "fp"}.get(base, base)
    groups.setdefault(normalized_base, {})[offset] = chr(value)


def _flush_asm_stack_groups(groups: dict[str, dict[int, str]], file_offset: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for base, chars_by_offset in groups.items():
        if len(chars_by_offset) < _MIN_LEN:
            continue
        offsets = sorted(chars_by_offset)
        run: list[tuple[int, str]] = []

        def emit(current: list[tuple[int, str]]) -> None:
            if len(current) < _MIN_LEN:
                return
            decoded = "".join(ch for _, ch in current)
            if not _is_printable_string(decoded):
                return
            results.append(
                {
                    "addr": hex(file_offset),
                    "raw_hex": decoded.encode("ascii", errors="replace").hex(),
                    "decoded": decoded,
                    "method": "stackstring-asm",
                    "confidence": "medium",
                    "base": base,
                }
            )

        previous: int | None = None
        for offset in offsets:
            ch = chars_by_offset[offset]
            if previous is not None and offset != previous + 1:
                emit(run)
                run = []
            run.append((offset, ch))
            previous = offset
        emit(run)
    return results


def _scan_asm_stackstrings(text: str, file_offset: int = 0) -> list[dict[str, Any]]:
    """Détecte des stackstrings depuis un listing assembleur texte.

    Couvre les formes directes x86 (`mov byte ptr [rbp-1], 0x41`) et les
    formes load-immediate + store-byte fréquentes en ARM/RISC-V/MIPS.
    """
    groups: dict[str, dict[int, str]] = {}
    register_values: dict[str, int] = {}

    for raw_line in str(text or "").splitlines():
        line = raw_line.split(";", 1)[0].split("# ", 1)[0].strip()
        if not line:
            continue
        lower = line.lower()

        direct = re.search(
            r"\bmov\b.*(?:byte\s+ptr\s+)?(?P<mem>\[[^\]]+\]|[-+]?(?:0x[0-9a-f]+|\d+)\s*\([^)]+\))\s*,\s*#?(?P<imm>0x[0-9a-f]+|\d+)",
            lower,
        )
        if direct:
            location = _asm_stack_location(direct.group("mem"))
            value = _parse_asm_int(direct.group("imm"))
            if location and value is not None:
                base, offset = location
                _record_asm_stack_char(groups, base, offset, value)
            continue

        imm_load = re.search(
            r"\b(?:movz|mov|li|la)\b\s+(?P<reg>[$%]?[a-z][a-z0-9]*)\s*,\s*#?(?P<imm>0x[0-9a-f]+|\d+)",
            lower,
        )
        if not imm_load:
            imm_load = re.search(
                r"\b(?:addi|addiu|daddiu)\b\s+(?P<reg>[$%]?[a-z][a-z0-9]*)\s*,\s*(?:zero|\$zero|\$0|x0)\s*,\s*#?(?P<imm>0x[0-9a-f]+|\d+)",
                lower,
            )
        if imm_load:
            value = _parse_asm_int(imm_load.group("imm"))
            reg = imm_load.group("reg").lstrip("$%")
            if value is not None and 0 <= value <= 0xFF:
                register_values[reg] = value
            continue

        store = re.search(
            r"\b(?:strb|sb|st\.b)\b\s+(?P<reg>[$%]?[a-z][a-z0-9]*)\s*,\s*(?P<mem>\[[^\]]+\]|[-+]?(?:0x[0-9a-f]+|\d+)\s*\([^)]+\))",
            lower,
        )
        if store:
            reg = store.group("reg").lstrip("$%")
            value = register_values.get(reg)
            location = _asm_stack_location(store.group("mem"))
            if value is not None and location:
                base, offset = location
                _record_asm_stack_char(groups, base, offset, value)

    return _flush_asm_stack_groups(groups, file_offset)


def _extract_candidate_regions(
    data: bytes, min_len: int = 6
) -> list[tuple[int, bytes]]:
    """Extrait les séquences de bytes non-ASCII consécutifs (candidats obfusqués)."""
    regions = []
    i = 0
    while i < len(data):
        if data[i] > 0x7E or data[i] < 0x09:
            start = i
            while i < len(data) and (data[i] > 0x7E or data[i] < 0x09):
                i += 1
            if i - start >= min_len:
                regions.append((start, data[start:i]))
        else:
            i += 1
    return regions


def _scan_xor_windows(
    region: bytes,
    *,
    base_offset: int,
    offset_map: dict[int, int],
    min_len: int = 6,
    max_window_len: int = 48,
) -> list[dict[str, Any]]:
    """Découpe une région non-ASCII en fenêtres glissantes pour retrouver plusieurs XOR.

    Cas visé : plusieurs strings XOR adjacentes avec des clés différentes qui
    fusionnent en une seule région candidate indécodable dans son ensemble.
    """
    if len(region) < (min_len * 2):
        return []

    hits: list[dict[str, Any]] = []
    cursor = 0
    window_cap = max(min_len, min(max_window_len, len(region)))

    while cursor <= len(region) - min_len:
        best_hit: dict[str, Any] | None = None
        max_end = min(len(region), cursor + window_cap)

        for end in range(max_end, cursor + min_len - 1, -1):
            window = region[cursor:end]
            candidate = _best_xor_candidate(window)
            if candidate is None:
                continue

            hit = dict(candidate)
            hit["offset"] = cursor
            hit["end"] = end
            hit["raw_hex"] = window.hex()
            abs_offset = base_offset + cursor
            hit["addr"] = hex(offset_map.get(abs_offset, abs_offset))

            if best_hit is None:
                best_hit = hit
                continue

            current_len = hit["end"] - hit["offset"]
            best_len = best_hit["end"] - best_hit["offset"]
            if (hit["score"], current_len) > (best_hit["score"], best_len):
                best_hit = hit

        if best_hit is not None:
            hits.append(
                {
                    "addr": best_hit["addr"],
                    "raw_hex": best_hit["raw_hex"],
                    "decoded": best_hit["decoded"],
                    "method": best_hit["method"],
                    "confidence": best_hit["confidence"],
                }
            )
            cursor = best_hit["end"]
            continue

        cursor += 1

    return hits


def _scan_rot_ascii(data: bytes, offset_map: dict[int, int], min_len: int = 8) -> list[dict[str, Any]]:
    """Scanne les runs de bytes ASCII printable et tente une décodage ROT-N.

    Les strings obfusquées par ROT sont elles-mêmes des bytes ASCII printable,
    donc invisibles pour _extract_candidate_regions (qui ne traite que le non-ASCII).
    On ne rapporte un hit que si le score anglais après décodage est nettement
    supérieur au score original (ratio ≥ 1.8) pour limiter les faux positifs.
    """
    results: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()

    i = 0
    while i < len(data):
        if 0x20 <= data[i] <= 0x7E:
            start = i
            while i < len(data) and 0x20 <= data[i] <= 0x7E:
                i += 1
            length = i - start
            if length < min_len:
                continue
            blob = data[start:i]
            orig_text = blob.decode("ascii", errors="replace")
            orig_score = _english_score(orig_text)
            rot_result = _try_rot(blob)
            if rot_result is None:
                continue
            decoded, n = rot_result
            dec_score = _english_score(decoded)
            # Require meaningfully better English score and not already English
            if dec_score <= 0 or dec_score < orig_score * 1.5:
                continue
            if start in seen_offsets:
                continue
            seen_offsets.add(start)
            vaddr = offset_map.get(start, start)
            results.append({
                "addr": hex(vaddr),
                "raw_hex": orig_text,
                "decoded": decoded,
                "method": f"ROT-{n}",
                "confidence": "low",
            })
        else:
            i += 1

    return results


def _dedupe_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in results:
        key = (
            str(item.get("addr", "")),
            str(item.get("decoded", "")),
            str(item.get("method", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def deobfuscate_strings(binary_path: str) -> list[dict[str, Any]]:
    """Tente de déobfusquer les strings encodées dans le binaire."""
    path = Path(binary_path)
    try:
        data = path.read_bytes()
    except Exception as e:
        _log.warning("Cannot read binary %s: %s", binary_path, e)
        return []

    # Build file-offset → virtual-address mapping (empty dict = use raw offsets)
    offset_map = _build_offset_to_vaddr(binary_path)
    candidate_keys = _extract_hardcoded_key_candidates(data)

    results: list[dict[str, Any]] = []

    # 1. Base64 scan (whole binary)
    results.extend(_scan_base64(data, offset_map))

    # 2. Stackstring detection (x86-64 and ARM64)
    results.extend(_scan_stackstrings(data, offset_map))
    if path.suffix.lower() in {".asm", ".s"} or b"\n" in data[:4096]:
        try:
            asm_text = data.decode("utf-8", errors="ignore")
        except Exception:
            asm_text = ""
        if asm_text:
            results.extend(_scan_asm_stackstrings(asm_text))

    # 3. ROT scan on ASCII printable runs (ROT strings are themselves printable)
    results.extend(_scan_rot_ascii(data, offset_map))

    # 4. RC4 / AES-ECB autour des clés hardcodées plausibles
    results.extend(_scan_stream_cipher_regions(data, offset_map, candidate_keys))

    # 5. XOR / ROT on non-ASCII candidate regions
    for offset, region in _extract_candidate_regions(data):
        addr = hex(offset_map.get(offset, offset))
        window_hits = _scan_xor_windows(
            region,
            base_offset=offset,
            offset_map=offset_map,
        )
        xor_result = _best_xor_candidate(region)
        if xor_result:
            if len(window_hits) >= 2:
                results.extend(window_hits)
                continue
            results.append(
                {
                    "addr": addr,
                    "raw_hex": region.hex(),
                    "decoded": xor_result["decoded"],
                    "method": xor_result["method"],
                    "confidence": xor_result["confidence"],
                }
            )
            continue

        rot_result = _try_rot(region)
        if rot_result:
            decoded, n = rot_result
            results.append(
                {
                    "addr": addr,
                    "raw_hex": region.hex(),
                    "decoded": decoded,
                    "method": f"ROT-{n}",
                    "confidence": "low",
                }
            )
            continue

        results.extend(
            window_hits
        )

    return _dedupe_results(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(deobfuscate_strings(args.binary), indent=2))
