#!/usr/bin/env python3
"""
AEGIS — Appendix D. Canonical form and hash of the Core (Section 10, B-7).

Status: working material. Prepared with the help of AI according to the instructions of the project owner;
requires independent review. The script does not assert the authenticity of the Core — it only computes the
hash under open rules so that anyone can repeat the computation (K-10).
English version of «AEGIS_приложение_хеш_ядра.py»; the rules and code are the same, so the hashes are identical.

RUN:
  python3 AEGIS_appendix_D_core_hash.py AEGIS_License_RU.md AEGIS_License_EN.md
  python3 AEGIS_appendix_D_core_hash.py --selftest

RULES (B-7):
 1. Only the Core is hashed: from the heading line of Part I («# ЧАСТЬ I» / «# PART I») inclusive
    to the last line «---» preceding the heading of Part II, exclusive.
 2. Normalization: UTF-8 without BOM; Unicode NFC; LF line endings; trailing spaces and tabs are
    removed; empty lines at the beginning and end are removed; the text ends with exactly one LF.
 3. Algorithms: SHA-512 and SHA3-512 (both mandatory; different constructions — Merkle–Damgård and sponge),
    so that one attack on the design of a function does not affect both. Truncation is not allowed.
 4. The hash of each language separately and the hash of the pair — of the ASCII string
    "AEGIS-CORE\nALG <algorithm>\nRU <RU hash>\nEN <EN hash>\n" with the same algorithm.
 5. The License identifier is the full hash of the pair under both algorithms. A short label (the first
    8 characters of SHA-512) only helps people recognize it and confirms nothing.
 6. Renewal (B-7, following RFC 4998): when a new algorithm is added, a renewal record is computed — a hash
    under the new algorithm of the previous record together with all earlier hashes and a timestamp; this moves
    the proof to the new algorithm while the earlier ones are still secure, and no earlier hash is lost.
"""
import hashlib
import sys
import unicodedata

STARTS = ("# ЧАСТЬ I.", "# PART I.")
NEXT = ("# ЧАСТЬ II.", "# PART II.")


def extract_core(text: str) -> str:
    text = text.lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    start = next(i for i, l in enumerate(lines) if l.strip().startswith(STARTS))
    end = next(i for i, l in enumerate(lines) if i > start and l.strip().startswith(NEXT))
    # remove the separator «---» and empty lines before Part II
    while end > start and lines[end - 1].strip() in ("", "---"):
        end -= 1
    return "\n".join(lines[start:end])


def canonical(core: str) -> bytes:
    core = unicodedata.normalize("NFC", core)
    core = core.replace("\r\n", "\n").replace("\r", "\n")
    lines = [l.rstrip(" \t") for l in core.split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return ("\n".join(lines) + "\n").encode("utf-8")


ALGS = {"sha512": hashlib.sha512, "sha3_512": hashlib.sha3_512}


def digests(b: bytes, algs=ALGS) -> dict:
    return {a: f(b).hexdigest() for a, f in algs.items()}


def pair(ru: dict, en: dict, algs=ALGS) -> dict:
    out = {}
    for alg, f in algs.items():
        s = f"AEGIS-CORE\nALG {alg}\nRU {ru[alg]}\nEN {en[alg]}\n".encode("ascii")
        out[alg] = f(s).hexdigest()
    return out


def identifier(p: dict) -> str:
    """Full identifier: both hashes of the pair without truncation."""
    return "AEGIS:" + ";".join(f"{a}={p[a]}" for a in sorted(p))


def label(p: dict) -> str:
    """A label for people — not for verification."""
    return "AEGIS·" + p["sha512"][:8]


def renewal_record(previous: str, old_hashes: dict, timestamp: str, new_alg: str, new_f) -> str:
    """Renewal record: the new algorithm binds the previous record, all earlier hashes and a timestamp."""
    body = "AEGIS-RENEWAL\nPREV " + previous + "\n" + "".join(f"OLD {a} {old_hashes[a]}\n" for a in sorted(old_hashes)) \
           + f"TIME {timestamp}\nALG {new_alg}\n"
    return f"{new_alg}=" + new_f(body.encode("ascii")).hexdigest()


def hash_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return digests(canonical(extract_core(fh.read())))


def selftest() -> None:
    # the test text is Russian on purpose: the rules must work for both languages and for non-ASCII letters
    base = "Шапка\n---\n# ЧАСТЬ I. ЯДРО\n\n**K-1.** Ёж й.\n\n---\n\n# ЧАСТЬ II. ИЗМЕНЯЕМАЯ ЧАСТЬ\nX\n"
    h = digests(canonical(extract_core(base)))
    variants = {
        "CRLF": base.replace("\n", "\r\n"),
        "BOM": "﻿" + base,
        "trailing spaces": base.replace("Ёж й.", "Ёж й.   "),
        "NFD (decomposed letters)": unicodedata.normalize("NFD", base),
        "different header and Part II": base.replace("Шапка", "Иное").replace("\nX\n", "\nY\n"),
    }
    for name, v in variants.items():
        assert digests(canonical(extract_core(v))) == h, name
        print(f"  does not change the hash: {name} — correct")
    changed = base.replace("Ёж", "Еж")
    assert digests(canonical(extract_core(changed))) != h
    print("  changes the hash: replacing one letter in the Core — correct")
    assert all(len(x) == 128 for x in h.values())
    print("  each hash is 512 bits long, no truncation — correct")
    r1 = renewal_record("start", h, "2030-01-01T00:00:00Z", "sha3_512", hashlib.sha3_512)
    h2 = dict(h); h2["sha512"] = "0" * 128
    assert renewal_record("start", h2, "2030-01-01T00:00:00Z", "sha3_512", hashlib.sha3_512) != r1
    assert renewal_record("start", h, "2031-01-01T00:00:00Z", "sha3_512", hashlib.sha3_512) != r1
    print("  the renewal record depends on every earlier hash and on the timestamp — correct")
    print("Self-check passed.")


if __name__ == "__main__":
    files = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--selftest" in sys.argv or len(files) < 2:
        selftest()
        if len(files) < 2:
            sys.exit(0)
    ru, en = hash_file(files[0]), hash_file(files[1])
    p = pair(ru, en)
    for name, d in (("RU", ru), ("EN", en), ("Pair RU+EN", p)):
        print(f"{name}:\n  SHA-512   {d['sha512']}\n  SHA3-512  {d['sha3_512']}")
    print("Identifier:", identifier(p))
    print("Label (for recognition only):", label(p))
