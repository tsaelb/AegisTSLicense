"""Сверка RU- и EN-версий приложения: обе запускаются, из вывода извлекаются все числа, последовательности должны совпасть.
EN: compares the RU and EN versions of an appendix: both are run, all numbers are extracted from the output, the sequences must match."""
import re, subprocess, sys, os
NUM = re.compile(r"[-−]?\d+(?:[.,]\d+)?(?:e[-+]?\d+)?")
def nums(path, args):
    path = os.path.abspath(path); r = subprocess.run([sys.executable, "-I", path] + args, capture_output=True, text=True, timeout=900, cwd=os.path.dirname(os.path.abspath(path)))
    if r.returncode != 0:
        return None, r.stderr[-400:]
    return [x.replace("−", "-").replace(",", ".") for x in NUM.findall(r.stdout)], ""
def compare(ru, en, args=()):
    a, ea = nums(ru, list(args)); b, eb = nums(en, list(args))
    if a is None or b is None:
        return False, f"ошибка запуска: {ea or eb}"
    if a == b:
        return True, f"чисел {len(a)}, совпадают"
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return False, f"расхождение в числе #{i}: RU {x} / EN {y} (всего RU {len(a)}, EN {len(b)})"
    return False, f"разное количество чисел: RU {len(a)}, EN {len(b)}"
if __name__ == "__main__":
    ok, msg = compare(sys.argv[1], sys.argv[2], sys.argv[3:])
    print(("[OK ] " if ok else "[ОШИБКА] ") + msg); sys.exit(0 if ok else 1)
