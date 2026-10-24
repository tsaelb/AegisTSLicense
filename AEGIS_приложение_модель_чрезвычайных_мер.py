#!/usr/bin/env python3
"""
AEGIS — Приложение к разделу «Чрезвычайные меры» (Ч).
Часть 1: проверка правил перебором всех последовательностей действий на горизонте HORIZON дней.
Часть 2: машинное доказательство индуктивного инварианта для ЛЮБОЙ длины последовательности (Z3, если установлен).
Статус: рабочий материал; подготовлено с помощью ИИ по указаниям владельца проекта; требует независимой проверки.
ЗАПУСК: python3 AEGIS_приложение_модель_чрезвычайных_мер.py [--naive]   (--naive добавляет наивную схему; нужно ~2 ГБ памяти)
"""

from collections import deque
import sys

T = {1: 3, 2: 14, 3: 1}
MAXREN = 2
CAP = 30
HORIZON = 60

def succ(s, design):
    day, cls, left, ren, counted, actual, quorum, imminent, kchg = s
    out = []
    if cls:
        nl = left - 1
        out.append(("день", (day + 1, cls if nl > 0 else 0, max(nl, 0), ren if nl > 0 else 0,
                             min(counted + 1, CAP + 1), min(actual + 1, CAP + 1), quorum, imminent, kchg)))
    else:
        out.append(("день", (day + 1, 0, 0, 0, counted, actual, quorum, imminent, kchg)))
    out.append(("кворум±", (day, cls, left, ren, counted, actual, not quorum, imminent, kchg)))
    out.append(("риск±", (day, cls, left, ren, counted, actual, quorum, not imminent, kchg)))
    if cls == 0:
        for c in (1, 2, 3):
            if c == 3 and not quorum and not imminent:
                continue
            if design == "fixed" and counted + T[c] > CAP:
                continue
            if design == "flawed" and counted >= CAP:
                continue
            out.append((f"объявить кл.{c}", (day, c, T[c], 0, counted, actual, quorum, imminent, kchg)))
            if design == "naive":
                out.append((f"переобъявить как новый кл.{c}", (day, c, T[c], 0, 0, actual, quorum, imminent, kchg)))
    else:
        if ren < MAXREN and (design == "naive" or counted + left + T[cls] <= CAP):
            out.append(("продлить", (day, cls, left + T[cls], ren + 1, counted, actual, quorum, imminent, kchg)))
        out.append(("отменить", (day, 0, 0, 0, counted, actual, quorum, imminent, kchg)))
    # полная независимая проверка открывает новое окно (мера должна быть заново обоснована)
    out.append(("полная проверка", (day, cls, left, ren, 0, 0, quorum, imminent, kchg)))
    return out

def run(design):
    start = (0, 0, 0, 0, 0, 0, True, False, False)
    parent = {start: None}; q = deque([start]); bad = {}
    while q:
        s = q.popleft()
        if s[5] > CAP: bad.setdefault("P2", s)
        if s[8]: bad.setdefault("P3", s)
        if s[0] >= HORIZON: continue
        for a, n in succ(s, design):
            if a.endswith("кл.3") and not s[6] and not s[7] and n not in parent:
                parent[n] = (s, a); bad.setdefault("P1", n)
            if n not in parent:
                parent[n] = (s, a); q.append(n)
    return parent, bad

def path(parent, s):
    p = []
    while parent[s]:
        s, a = parent[s][0], parent[s][1]; p.append(a)
    p.reverse(); out = []
    for a in p:
        if a in ("кворум±", "риск±"): continue
        if out and out[-1][0] == a: out[-1][1] += 1
        else: out.append([a, 1])
    return " → ".join(f"{a}×{k}" if k > 1 else a for a, k in out)

designs = (["naive"] if "--naive" in sys.argv else []) + ["flawed", "fixed"]
for design in designs:
    parent, bad = run(design)
    print(f"Схема «{design}»: состояний {len(parent)}; нарушены свойства: {sorted(bad) or 'нет'}")
    for prop, s in sorted(bad.items()):
        print(f"  {prop}, контрпример: {path(parent, s)}")


# ---------------- Часть 2. Индуктивное доказательство (схема «fixed») ----------------
# Инвариант I: 0 <= counted, 0 <= left, counted + left <= CAP, actual == counted.
# Доказываем: для любых целых значений и любого допустимого перехода I => I'.
try:
    import z3
except ImportError:
    print("\nZ3 не установлен (pip install z3-solver) — индуктивное доказательство пропущено"); raise SystemExit
counted, left, actual, Tc, cap = z3.Ints("counted left actual Tc CAP")
c2, l2, a2 = z3.Ints("counted2 left2 actual2")
I = lambda c, l, a: z3.And(c >= 0, l >= 0, c + l <= cap, a == c)
params = z3.And(cap >= 1, Tc >= 1, Tc <= cap)
transitions = {
 "день под мерой": z3.And(left >= 1, c2 == counted + 1, l2 == left - 1, a2 == actual + 1),
 "день без меры": z3.And(left == 0, c2 == counted, l2 == 0, a2 == actual),
 "объявить меру": z3.And(left == 0, counted + Tc <= cap, c2 == counted, l2 == Tc, a2 == actual),
 "продлить": z3.And(left >= 1, counted + left + Tc <= cap, c2 == counted, l2 == left + Tc, a2 == actual),
 "отменить": z3.And(c2 == counted, l2 == 0, a2 == actual),
 "полная проверка": z3.And(c2 == 0, l2 == left, a2 == 0, left <= cap),
}
print("\nИндуктивное доказательство инварианта I для любой длины последовательности:")
s = z3.Solver(); s.add(cap >= 1, z3.Not(I(0, 0, 0)))
print("  база (начальное состояние):", "доказано" if s.check() == z3.unsat else "НЕ доказано")
allok = True
for name, tr in transitions.items():
    s = z3.Solver(); s.add(params, I(counted, left, actual), tr, z3.Not(I(c2, l2, a2)))
    r = s.check(); allok &= r == z3.unsat
    print(f"  шаг «{name}»:", "сохраняет инвариант" if r == z3.unsat else f"НАРУШАЕТ, контрпример {s.model()}")
print("  вывод:", "I верен для всех достижимых состояний; значит actual <= CAP всегда (свойство P2)" if allok else "доказательство не получено")
# Контроль: «ошибочная» версия правила объявления не сохраняет инвариант
s = z3.Solver(); s.add(params, I(counted, left, actual), left == 0, counted < cap, c2 == counted, l2 == Tc, a2 == actual, z3.Not(I(c2, l2, a2)))
print("  контроль: правило «объявлять, пока лимит не исчерпан» —", "опровергнуто, контрпример " + str(s.model()) if s.check() == z3.sat else "не опровергнуто")
