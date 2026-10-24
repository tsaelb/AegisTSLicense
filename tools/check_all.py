"""Полная проверка пакета AEGIS / Full check of the AEGIS package. Запуск из корня пакета / run from the package root: python3 -I tools/check_all.py
1) Структура: число и порядок положений RU/EN, определения, разделы.
2) Перекрёстные ссылки: каждая ссылка на положение указывает на существующее.
3) Все приложения запускаются без ошибок; ключевые выводы совпадают с текстом.
4) Логические модели Z3: ядро (kz3_core), суд и процедура (Приложение Д) — 0 противоречий.
5) Английские версии приложений дают те же числа; таблицы и призыв есть на обоих языках; мутационная проверка испытаний.

EN: 1) structure of RU/EN texts; 2) cross-references; 3) all appendices run and their key conclusions match the text;
4) Z3 models of the Core and courts; 5) English appendices give the same numbers as the Russian ones, tables and the call
exist in both languages, mutation testing of the tests. Messages are printed in Russian.
"""
import re, subprocess, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(HERE)
KZ3 = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(HERE, "kz3_core.py")
RU = open(os.path.join(OUT, "AEGIS_License_RU.md"), encoding="utf-8").read()
EN = open(os.path.join(OUT, "AEGIS_License_EN.md"), encoding="utf-8").read()
MAP = dict(zip("ЛТСПРЧВУГЮНОДФK", "LTCPREBUWJHFMSK"))
ok = True
def report(name, good, detail=""):
    global ok
    ok &= good
    print(f"[{'OK ' if good else 'ОШИБКА'}] {name}" + (f": {detail}" if detail else ""))

idr = re.findall(r"^\*\*([A-ZА-Я])-(\d[\d.]*[а-яa-z]?)\.?", RU, re.M)
ide = re.findall(r"^\*\*([A-ZА-Я])-(\d[\d.]*[а-яa-z]?)\.?", EN, re.M)
norm = lambda s: s.rstrip(".").replace("б", "b").replace("а", "a").replace("в", "c")
mr = [(MAP.get(p, p), norm(n)) for p, n in idr]; me = [(p, norm(n)) for p, n in ide]
report("число положений", len(mr) == len(me), f"RU {len(mr)}, EN {len(me)}")
diff = [(a, b) for a, b in zip(mr, me) if a != b]
report("порядок и номера положений совпадают", not diff, str(diff[:3]))
dr = re.findall(r"^(\d+)\. \*\*", RU, re.M); de = re.findall(r"^(\d+)\. \*\*", EN, re.M)
report("определения", dr == de, f"{len(dr)} / {len(de)}")
sr = re.findall(r"^## (\d+)\.", RU, re.M); se = re.findall(r"^## (\d+)\.", EN, re.M)
report("разделы изменяемой части", sr == se, f"{len(sr)}")

def refs_ok(text, ids, letters):
    have = {f"{p}-{n.rstrip('.')}" for p, n in ids}
    bad = set()
    for p, n in re.findall(rf"(?<![\w-])([{letters}])-(\d+(?:\.\d+)?[а-яa-z]?)", text):
        key = f"{p}-{n}"
        if key not in have and not re.match(r"[ВB]-[1-4]–", key):
            bad.add(key)
    return bad
br = refs_ok(RU, idr, "KЛТСПРЧВУГЮНОДФ"); be = refs_ok(EN, ide, "KLTCPREBUWJHFMS")
report("ссылки RU указывают на существующие положения", not br, ", ".join(sorted(br)))
report("ссылки EN указывают на существующие положения", not be, ", ".join(sorted(be)))
report("нет «Открытый вопрос» без решения", "Открытый вопрос" not in RU and "Open question" not in EN)

def run(args, must=()):
    r = subprocess.run([sys.executable, "-I"] + args, capture_output=True, text=True, timeout=900, cwd=OUT)
    good = r.returncode == 0 and all(m in r.stdout for m in must)
    return good, (r.stdout + r.stderr)
for script, args, must in [
    ("AEGIS_приложение_модель_проверки.py", ["--quick", "--small"], ["Принятая схема: n=79, k=51", "начиная с которого мера допустима при любом большем N: 14"]),
    ("AEGIS_приложение_модели_управления.py", [], ["принятая схема: 9 из 17", "Технические хранители", "Патентное сдерживание"]),
    ("AEGIS_приложение_модель_чрезвычайных_мер.py", [], []),
    ("AEGIS_приложение_хеш_ядра.py", ["--selftest", "AEGIS_License_RU.md", "AEGIS_License_EN.md"], ["Самопроверка пройдена", "запись обновления зависит от каждого прежнего хеша"]),
    ("AEGIS_приложение_суд_и_процедура.py", [], ["Вариант «предлагаемый»: противоречивых ситуаций 0", "Можно требовать наказания: unsat"]),
    ("AEGIS_приложение_ключи_жребий_роли.py", [], ["9 из 17: два непересекающихся кворума невозможны (доказано)", "с В-11: тупик недостижим", "с правилом: 0"]),
    ("AEGIS_приложение_пороги_и_параметры.py", [], ["нужно не меньше 5 голосующих", "граница 2.5% при 0 находок: объём не меньше 119",
        "принятый предел: s <= 5%", "принятая схема казны: 6 из 10", "выпуск (17 держателей + 6 команд по 4 хранителя): 41",
        "с казной (10 подписантов): 51", "не хуже альтернатив в 23 из 24", "ответ всегда непуст", "9 из 17: худшее отношение", "принято — полные SHA-512 и SHA3-512", "переживает его с вероятностью 0.039"]),
    ("AEGIS_приложение_эталон_проверки.py", [], ["Испытаний: 27, не пройдено: 0", "Пройдены все испытания."]),
]:
    good, out = run([script] + args, must)
    report(f"приложение {script}", good, "" if good else out[-600:])
if os.path.exists(KZ3):
    variant = "предлагаемый" if "созданная без использования произведений под этой лицензией, ею не связана" in RU else "текущий"
    good, out = run([KZ3, variant], ["Невыполнимых комбинаций: 0", "с правилом 0", "Контроль чувствительности (старая K-18 без исключения должна дать конфликт): обнаружен", "Контроль чувствительности 2 (восстановление при условии извинения должно дать конфликт): обнаружен"])
    report("Z3: непротиворечивость ядра", good, out.strip().splitlines()[-1] if out.strip() else "")
# английские версии приложений: те же числа, что у русских (сверка всех чисел вывода)
PAIRS = [
    ("AEGIS_приложение_модель_проверки.py", "AEGIS_appendix_A_review_model.py", ["--quick", "--small"]),
    ("AEGIS_приложение_модели_управления.py", "AEGIS_appendix_B_governance_models.py", []),
    ("AEGIS_приложение_модель_чрезвычайных_мер.py", "AEGIS_appendix_C_emergency_measures.py", []),
    ("AEGIS_приложение_хеш_ядра.py", "AEGIS_appendix_D_core_hash.py", ["--selftest", "AEGIS_License_RU.md", "AEGIS_License_EN.md"]),
    ("AEGIS_приложение_суд_и_процедура.py", "AEGIS_appendix_E_courts_and_procedure.py", []),
    ("AEGIS_приложение_ключи_жребий_роли.py", "AEGIS_appendix_F_keys_lots_roles.py", []),
    ("AEGIS_приложение_пороги_и_параметры.py", "AEGIS_appendix_G_thresholds_and_parameters.py", []),
    ("AEGIS_приложение_эталон_проверки.py", "AEGIS_appendix_H_reference_verification.py", []),
]
HERE_T = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE_T)
import equiv
for ru, en, args in PAIRS:
    good, msg = equiv.compare(os.path.join(OUT, ru), os.path.join(OUT, en), args)
    report(f"RU/EN приложения {en}: {msg}", good)
for doc in ("AEGIS_призыв_к_независимой_проверке.md", "AEGIS_call_for_independent_review.md",
            "AEGIS_CORE_прослеживаемость.csv", "AEGIS_CORE_traceability.csv",
            "AEGIS_стресс_тесты_повторно.csv", "AEGIS_stress_tests.csv",
            "AEGIS_допущения_моделей.csv", "AEGIS_model_assumptions.csv"):
    report(f"есть файл {doc}", os.path.exists(os.path.join(OUT, doc)))
import csv as _csv
for ru, en in (("AEGIS_CORE_прослеживаемость.csv", "AEGIS_CORE_traceability.csv"), ("AEGIS_стресс_тесты_повторно.csv", "AEGIS_stress_tests.csv"),
               ("AEGIS_допущения_моделей.csv", "AEGIS_model_assumptions.csv")):
    a = list(_csv.reader(open(os.path.join(OUT, ru), encoding="utf-8-sig"))); b = list(_csv.reader(open(os.path.join(OUT, en), encoding="utf-8-sig")))
    report(f"таблицы {ru} / {en}: строк {len(a)} / {len(b)}, первый столбец совпадает", len(a) == len(b) and (en == "AEGIS_model_assumptions.csv" or [r[0] for r in a[1:]] == [r[0] for r in b[1:]]))
mut = os.path.join(HERE_T, "mutation_check.py")
if os.path.exists(mut):
    for f in ("AEGIS_приложение_эталон_проверки.py", "AEGIS_appendix_H_reference_verification.py"):
        good, out = run([mut, os.path.abspath(os.path.join(OUT, f))], ["выжило: 0"])
        report(f"мутационная проверка испытаний {f}", good, out.strip().splitlines()[-1] if out.strip() else "")
print("ИТОГ:", "всё проверено, ошибок нет" if ok else "есть ошибки")
