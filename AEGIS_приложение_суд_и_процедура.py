#!/usr/bin/env python3
"""
AEGIS — Приложение Д. Суд и процедура проекта (раздел 13, Ю-6 … Ю-9).
Статус: рабочий материал. Подготовлено с помощью ИИ по указаниям владельца проекта; требует
независимой проверки. Перевод положений в формулы сделан составителем и сам требует проверки (K-10).
ЗАПУСК: python3 AEGIS_приложение_суд_и_процедура.py   (нужен пакет z3-solver)
Допущения части 2: ошибки суда и раздела 7 независимы при данной истине; частоты ошибок раздела 7 — из Приложения А.
"""

import itertools, z3, sys

F = ["f_sec7_done", "f_sec7_found", "f_sec7_stalled", "f_need_court", "f_court_found",
     "f_court_binding", "f_order_contrary_core", "f_harm_people", "f_order_restricts", "f_imminent"]
A = ["a_sue", "a_claim_cessation", "a_claim_punitive", "a_claim_restitution", "a_comply_order",
     "a_disclose_coercion", "a_treat_as_interpretation", "a_restrict", "a_publish_both", "a_rereview", "a_edit_K"]
v = {n: z3.Bool(n) for n in F + A}
I, And, Or, Not = z3.Implies, z3.And, z3.Or, z3.Not

core = {
 "K-15 без наказания": Not(v["a_claim_punitive"]),
 "K-15 ограничение только при доказанном": I(And(v["a_restrict"], Not(v["a_comply_order"])), v["f_sec7_found"]),
 "K-23 власть не толкует ядро": Not(v["a_treat_as_interpretation"]),
 "K-0.9 принуждение раскрывается": I(And(v["a_comply_order"], v["f_order_contrary_core"]), v["a_disclose_coercion"]),
 "K-0.2 ядро не меняется": Not(v["a_edit_K"]),
}
facts_logic = {
 "раздел 7: найдено только по завершении": I(v["f_sec7_found"], v["f_sec7_done"]),
 "задержка — значит не завершено": I(v["f_sec7_stalled"], Not(v["f_sec7_done"])),
}

def rules(variant):
    r = {
     "Ю-6 право на суд": I(And(v["f_need_court"], Or(v["f_sec7_done"], v["f_sec7_stalled"], v["f_imminent"])), v["a_sue"]),
     "Ю-7(а) иск — только прекращение или возмещение": I(v["a_sue"], Or(v["a_claim_cessation"], v["a_claim_restitution"])),
     "Ю-7(а) возмещение — только реального вреда людям": I(v["a_claim_restitution"], v["f_harm_people"]),
     "Ю-8(б) обязательное решение суда исполняется": I(v["f_court_binding"], v["a_comply_order"]),
 "смысл: решение суда требует ограничить права": I(And(v["a_comply_order"], v["f_order_restricts"]), v["a_restrict"]),
     "Ю-9(в) расхождение: публикуются оба решения": I(And(v["f_sec7_done"], v["f_court_found"] != v["f_sec7_found"]), v["a_publish_both"]),
    }
    if variant == "строгий «сначала процедура»":
        r["Ю-6 право на суд"] = I(v["f_need_court"], v["a_sue"])
        r["Ю-7(а) иск только после раздела 7"] = I(v["a_sue"], v["f_sec7_done"])
    if variant == "следовать разделу 7 без оговорки о принуждении":
        r["Ю-9(в) проект следует разделу 7"] = I(v["f_sec7_done"], v["a_restrict"] == v["f_sec7_found"])
    if variant == "предлагаемый":
        r["Ю-6 иск после раздела 7, его задержки или при непосредственном риске"] = I(v["a_sue"], Or(v["f_sec7_done"], v["f_sec7_stalled"], v["f_imminent"]))
        r["Ю-9(в) следовать разделу 7, если нет принуждения"] = I(And(v["f_sec7_done"], Not(v["a_comply_order"])), v["a_restrict"] == v["f_sec7_found"])
    return r

def run(variant):
    bad = {}
    for bits in itertools.product([False, True], repeat=len(F)):
        s = z3.Solver(); tags = {}
        for name, c in {**core, **facts_logic, **rules(variant)}.items():
            t = z3.Bool("T:" + name); tags[str(t)] = name; s.assert_and_track(c, t)
        fa = [v[f] if b else Not(v[f]) for f, b in zip(F, bits)]
        s.add(*fa)
        # исключить сами по себе невозможные обстоятельства
        s0 = z3.Solver(); s0.add(*facts_logic.values(), *fa)
        if s0.check() == z3.unsat:
            continue
        if s.check() == z3.unsat:
            k = tuple(sorted(tags[str(c)] for c in s.unsat_core()))
            bad[k] = bad.get(k, 0) + 1
    return bad

print("=== 1. Z3: выполнимость правил вместе с ядром (перебор 2^10 обстоятельств) ===")
for var in ["строгий «сначала процедура»", "следовать разделу 7 без оговорки о принуждении", "предлагаемый"]:
    bad = run(var)
    print(f"Вариант «{var}»: противоречивых ситуаций {sum(bad.values())}")
    for k, n in bad.items():
        print("   конфликт:", " + ".join(k), f"({n})")

# свидетельство: в предлагаемом варианте суд доступен, наказание невозможно
s = z3.Solver(); s.add(*core.values(), *facts_logic.values(), *rules("предлагаемый").values())
s.add(v["f_need_court"], v["f_sec7_stalled"]); print("Суд доступен при задержке процедуры:", s.check())
s2 = z3.Solver(); s2.add(*core.values(), *rules("предлагаемый").values(), v["a_claim_punitive"]); print("Можно требовать наказания:", s2.check())

print("\n=== 2. Ошибки при расхождении суда и раздела 7 (Приложение А: n=79, k=51) ===")
FPs, FNs = 9.2e-7, 0.026                 # раздел 7 (n=79, k=51): ложно «доказано» / ложно «не доказано»
w = 20                                    # ложное ограничение прав в w раз хуже пропуска (сомнение — в пользу ограничиваемого)
print(f"Потеря = {w}·P(ложное ограничение) + P(пропуск нарушения); суд: ложно «нарушение» c1, ложно «нет» c2")
for c1, c2 in [(0.01, 0.10), (0.05, 0.20), (0.10, 0.30)]:
    pol = {
     "следовать суду": (c1, c2),
     "следовать разделу 7": (FPs, FNs),
     "ограничивать, если любой нашёл": (1 - (1 - FPs) * (1 - c1), FNs * c2),
     "ограничивать, только если оба нашли": (FPs * c1, 1 - (1 - FNs) * (1 - c2)),
     "раздел 7 + повторная проверка при «суд: нет»": (FPs * (1 - c1) * FPs + FPs * c1, FNs + (1 - FNs) * (1 - c2) * FNs),
    }
    print(f" суд c1={c1}, c2={c2}:")
    for name, (fp, fn) in sorted(pol.items(), key=lambda x: w * x[1][0] + x[1][1]):
        print(f"   {name:45s} ложное ограничение {fp:.1e}, пропуск {fn:.3f}, потеря {w*fp+fn:.4f}")

thr = ((FNs + (1 - FNs) * 0.9 * FNs) - FNs) / (FPs - FPs * FPs)
print(f"Порог (суд c2=0.10): повторная проверка выгоднее, только если ложное ограничение хуже пропуска более чем в {thr:.0f} раз")
