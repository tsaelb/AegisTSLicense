#!/usr/bin/env python3
"""
AEGIS — Приложение Г. Каноническая форма и хеш ядра (раздел 10, В-7).

Статус: рабочий материал. Подготовлено с помощью ИИ по указаниям владельца проекта; требует
независимой проверки. Скрипт не утверждает подлинность ядра — он только вычисляет хеш
по открытым правилам, чтобы любой мог повторить вычисление (K-10).

ЗАПУСК:
  python3 AEGIS_приложение_хеш_ядра.py AEGIS_License_RU.md AEGIS_License_EN.md
  python3 AEGIS_приложение_хеш_ядра.py --selftest

ПРАВИЛА (В-7):
 1. Хешируется только ядро: от строки заголовка части I («# ЧАСТЬ I» / «# PART I») включительно
    до последней строки «---», предшествующей заголовку части II, не включая её.
 2. Нормализация: UTF-8 без BOM; Unicode NFC; концы строк LF; пробелы и табуляции в конце строк
    удаляются; пустые строки в начале и конце удаляются; текст оканчивается ровно одним LF.
 3. Алгоритмы: SHA-512 и SHA3-512 (оба обязательны; разные конструкции — Меркла — Дамгора и губка),
    чтобы одна атака на устройство функции не задевала обе. Усечение не допускается.
 4. Хеш каждого языка отдельно и хеш пары — от ASCII-строки
    "AEGIS-CORE\nALG <алгоритм>\nRU <хеш RU>\nEN <хеш EN>\n" тем же алгоритмом.
 5. Идентификатор лицензии — полный хеш пары обоими алгоритмами. Короткая метка (первые 8 знаков SHA-512)
    служит только человеку для узнавания и ничего не подтверждает.
 6. Обновление (В-7, по образцу RFC 4998): при добавлении нового алгоритма вычисляется запись обновления —
    хеш новым алгоритмом от прежней записи вместе со всеми прежними хешами и временной отметкой; так
    доказательство переходит на новый алгоритм, пока прежние ещё стойки, и ни один прежний хеш не теряется.
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
    # убрать разделитель «---» и пустые строки перед частью II
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
    """Полный идентификатор: оба хеша пары без усечения."""
    return "AEGIS:" + ";".join(f"{a}={p[a]}" for a in sorted(p))


def label(p: dict) -> str:
    """Метка для человека — не для проверки."""
    return "AEGIS·" + p["sha512"][:8]


def renewal_record(previous: str, old_hashes: dict, timestamp: str, new_alg: str, new_f) -> str:
    """Запись обновления: новый алгоритм связывает прежнюю запись, все прежние хеши и временную отметку."""
    body = "AEGIS-RENEWAL\nPREV " + previous + "\n" + "".join(f"OLD {a} {old_hashes[a]}\n" for a in sorted(old_hashes)) \
           + f"TIME {timestamp}\nALG {new_alg}\n"
    return f"{new_alg}=" + new_f(body.encode("ascii")).hexdigest()


def hash_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return digests(canonical(extract_core(fh.read())))


def selftest() -> None:
    base = "Шапка\n---\n# ЧАСТЬ I. ЯДРО\n\n**K-1.** Ёж й.\n\n---\n\n# ЧАСТЬ II. ИЗМЕНЯЕМАЯ ЧАСТЬ\nX\n"
    h = digests(canonical(extract_core(base)))
    variants = {
        "CRLF": base.replace("\n", "\r\n"),
        "BOM": "﻿" + base,
        "пробелы в конце строк": base.replace("Ёж й.", "Ёж й.   "),
        "NFD (разложенные буквы)": unicodedata.normalize("NFD", base),
        "другая шапка и часть II": base.replace("Шапка", "Иное").replace("\nX\n", "\nY\n"),
    }
    for name, v in variants.items():
        assert digests(canonical(extract_core(v))) == h, name
        print(f"  не меняет хеш: {name} — верно")
    changed = base.replace("Ёж", "Еж")
    assert digests(canonical(extract_core(changed))) != h
    print("  меняет хеш: замена одной буквы в ядре — верно")
    assert all(len(x) == 128 for x in h.values())
    print("  длина каждого хеша 512 бит, усечения нет — верно")
    r1 = renewal_record("start", h, "2030-01-01T00:00:00Z", "sha3_512", hashlib.sha3_512)
    h2 = dict(h); h2["sha512"] = "0" * 128
    assert renewal_record("start", h2, "2030-01-01T00:00:00Z", "sha3_512", hashlib.sha3_512) != r1
    assert renewal_record("start", h, "2031-01-01T00:00:00Z", "sha3_512", hashlib.sha3_512) != r1
    print("  запись обновления зависит от каждого прежнего хеша и от временной отметки — верно")
    print("Самопроверка пройдена.")


if __name__ == "__main__":
    files = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--selftest" in sys.argv or len(files) < 2:
        selftest()
        if len(files) < 2:
            sys.exit(0)
    ru, en = hash_file(files[0]), hash_file(files[1])
    p = pair(ru, en)
    for name, d in (("RU", ru), ("EN", en), ("Пара RU+EN", p)):
        print(f"{name}:\n  SHA-512   {d['sha512']}\n  SHA3-512  {d['sha3_512']}")
    print("Идентификатор:", identifier(p))
    print("Метка (только для узнавания):", label(p))
