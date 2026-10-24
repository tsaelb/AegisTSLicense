#!/usr/bin/env python3
"""
AEGIS — манифест пакета (В-7): SHA-512 и SHA3-512 каждого файла и полный идентификатор ядра.

  python3 -I tools/manifest.py make    # из корня пакета: пишет SHA512SUMS, SHA3-512SUMS, CORE-ID.txt
  python3 -I tools/manifest.py check   # сверяет все файлы с обоими манифестами

SHA512SUMS проверяется и стандартной командой: sha512sum -c SHA512SUMS
Подписи (.asc, .sig), отметки времени (.ots), открытые ключи (keys/) и служебные файлы git в манифест
не входят: они появляются после манифеста и сами его подтверждают.
"""
import hashlib, importlib.util, os, sys
sys.dont_write_bytecode = True

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFESTS = {"SHA512SUMS": hashlib.sha512, "SHA3-512SUMS": hashlib.sha3_512}
SKIP_DIRS = {".git", "keys", "__pycache__"}
SKIP_FILES = set(MANIFESTS) | {"CORE-ID.txt"}
SKIP_SUFFIX = (".sig", ".asc", ".ots", ".bak")


def files():
    out = []
    for d, dirs, fs in os.walk(ROOT):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for f in sorted(fs):
            rel = os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/")
            if rel in SKIP_FILES or rel.endswith(SKIP_SUFFIX):
                continue
            out.append(rel)
    return sorted(out)


def digest(path, f):
    h = f()
    with open(os.path.join(ROOT, path), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def core_id():
    spec = importlib.util.spec_from_file_location("g", os.path.join(ROOT, "AEGIS_приложение_хеш_ядра.py"))
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    ru = g.hash_file(os.path.join(ROOT, "AEGIS_License_RU.md"))
    en = g.hash_file(os.path.join(ROOT, "AEGIS_License_EN.md"))
    p = g.pair(ru, en)
    lines = ["Идентификатор лицензии AEGIS (Л-10, В-7) / AEGIS License identifier",
             g.identifier(p), "",
             "Метка для узнавания, ничего не подтверждает / Recognition label, confirms nothing:",
             g.label(p), ""]
    for name, d in (("RU", ru), ("EN", en)):
        lines += [f"Ядро {name} / Core {name}:", f"  sha512   {d['sha512']}", f"  sha3_512 {d['sha3_512']}"]
    return "\n".join(lines) + "\n"


def make():
    fl = files()
    for name, f in MANIFESTS.items():
        with open(os.path.join(ROOT, name), "w", encoding="utf-8", newline="\n") as out:
            for p in fl:
                out.write(f"{digest(p, f)}  {p}\n")
    with open(os.path.join(ROOT, "CORE-ID.txt"), "w", encoding="utf-8", newline="\n") as out:
        out.write(core_id())
    print(f"файлов в манифесте: {len(fl)}; записаны {', '.join(MANIFESTS)}, CORE-ID.txt")


def check():
    ok = True
    for name, f in MANIFESTS.items():
        listed = {}
        with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
            for line in fh:
                h, p = line.rstrip("\n").split("  ", 1)
                listed[p] = h
        for p, h in listed.items():
            if not os.path.exists(os.path.join(ROOT, p)) or digest(p, f) != h:
                ok = False
                print(f"НЕ СОВПАДАЕТ ({name}): {p}")
        extra = set(files()) - set(listed)
        for p in sorted(extra):
            ok = False
            print(f"НЕТ В МАНИФЕСТЕ ({name}): {p}")
    with open(os.path.join(ROOT, "CORE-ID.txt"), encoding="utf-8") as fh:
        if fh.read() != core_id():
            ok = False
            print("CORE-ID.txt не совпадает с вычисленным хешем ядра")
    print("Манифесты и идентификатор ядра совпадают." if ok else "ЕСТЬ РАСХОЖДЕНИЯ.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    {"make": make, "check": check}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
