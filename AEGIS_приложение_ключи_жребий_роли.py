#!/usr/bin/env python3
"""
AEGIS — Приложение Е. Ключи, жребий, разделение ролей, свежесть и записи дел
(В-4, В-10, В-11, В-12, У-8, П-13).

Статус: рабочий материал. Подготовлено с помощью ИИ по указаниям владельца проекта; требует
независимой проверки. Перевод положений в формулы сделан составителем и сам требует проверки (K-10).
ЗАПУСК: python3 AEGIS_приложение_ключи_жребий_роли.py   (нужен пакет z3-solver)

1. Единственность продолжения (Z3, доказательство для всех подмножеств): при подписи «t из n» с t > n/2
   два непересекающихся множества держателей не могут оба собрать t подписей; при t <= n/2 могут.
2. Восстановление набора ключей (В-11): если доступных держателей меньше t, обычная смена (В-2) невозможна
   навсегда — проверка перебором состояний; с правилом В-11 состояние «тупик» недостижимо.
3. Жребий (В-12): атака удержанием раскрытия в схеме «обязательство — раскрытие». Монте-Карло: смещение
   без внешнего источника и с внешним источником, неизвестным в момент решения о раскрытии.
4. Разделение ролей (У-8): вероятность, что один человек окажется одновременно в нескольких ролях
   (держатель ключа, хранитель, подписант казны), если роли распределяются жребием без запрета совмещения.
5. Свежесть статуса (В-4): атака откатом — скомпрометированные каналы показывают устаревший, но правильно
   подписанный статус (например, до отзыва ключа или выпуска). Вероятность принять его при правиле
   «совпадение в 2 каналах» и «совпадение в большинстве каналов» при компрометации с общей причиной.
6. Записи дел (П-13): Z3 — просьба удалить персональные данные, являющиеся доказательством в незавершённом
   деле, против запрета уничтожать доказательства: противоречие без правила, его отсутствие с правилом.
"""
import itertools, math, random, sys

try:
    import z3
except ImportError:
    z3 = None

def lcomb(a, b):
    return math.lgamma(a + 1) - math.lgamma(b + 1) - math.lgamma(a - b + 1) if 0 <= b <= a else -math.inf

def betabin(x, n, mean, rho):
    if rho <= 0:
        return math.exp(lcomb(n, x) + (x * math.log(mean) if x else 0) + ((n - x) * math.log(1 - mean) if n - x else 0))
    a = mean * (1 - rho) / rho; b = (1 - mean) * (1 - rho) / rho
    lb = lambda u, v: math.lgamma(u) + math.lgamma(v) - math.lgamma(u + v)
    return math.exp(lcomb(n, x) + lb(x + a, n - x + b) - lb(a, b))

# 1. Единственность продолжения ------------------------------------------------
def two_disjoint_quorums_possible(n, t):
    """Z3: существуют ли два непересекающихся множества держателей, каждое не меньше t."""
    A = [z3.Bool(f"a{i}") for i in range(n)]; B = [z3.Bool(f"b{i}") for i in range(n)]
    s = z3.Solver()
    s.add(*[z3.Not(z3.And(A[i], B[i])) for i in range(n)])
    s.add(z3.PbGe([(x, 1) for x in A], t), z3.PbGe([(x, 1) for x in B], t))
    return s.check() == z3.sat

# 2. Восстановление набора ключей ----------------------------------------------
def deadlock_reachable(n, t, with_recovery, steps=12):
    """Состояние — число доступных держателей k. Потеря ключа: k -> k-1. Смена (В-2): при k >= t набор
    пополняется до n. Восстановление (В-11): при k < t новый набор формируется по В-11 (жребий + голосование)."""
    seen = {n}; frontier = {n}
    for _ in range(steps):
        nxt = set()
        for k in frontier:
            if k > 0: nxt.add(k - 1)
            if k >= t: nxt.add(n)
            if k < t and with_recovery: nxt.add(n)
        frontier = nxt - seen; seen |= nxt
    # тупик — состояние, из которого недостижимо k >= t
    def can_recover(k):
        return k >= t or with_recovery
    return any(not can_recover(k) for k in seen)

# 3. Жребий ---------------------------------------------------------------------
def lottery_bias(members=20, attackers=3, seats=7, trials=20000, beacon=False, seed=1):
    """Цель противника — увеличить число своих мест. Без внешнего источника последний раскрывающий видит
    чужие раскрытия и для каждого своего участника решает «раскрыть / удержать» (нераскрывший выбывает из
    жребия), выбирая лучшее из 2^attackers исходов. С внешним источником (хеш блока на высоте, наступающей
    после срока раскрытия) исход в момент решения неизвестен — выбор не даёт информации."""
    rng = random.Random(seed)
    honest_expect = seats * attackers / members
    total = 0.0
    for _ in range(trials):
        honest_vals = [rng.getrandbits(32) for _ in range(members - attackers)]
        att_vals = [rng.getrandbits(32) for _ in range(attackers)]
        beacon_val = rng.getrandbits(32)
        def outcome(mask, bval):
            pool = [("h", i) for i in range(members - attackers)] + [("a", j) for j in range(attackers) if mask >> j & 1]
            seedv = hash((tuple(honest_vals), tuple(v for j, v in enumerate(att_vals) if mask >> j & 1), bval))
            r = random.Random(seedv); r.shuffle(pool)
            return sum(1 for p in pool[:seats] if p[0] == "a")
        if beacon:
            # решение принимается до появления значения внешнего источника: противник выбирает маску,
            # максимизирующую ожидание, но ожидание при любой маске одинаково ~ доле присутствующих
            mask = (1 << attackers) - 1
            total += outcome(mask, beacon_val)
        else:
            total += max(outcome(mask, None) for mask in range(1 << attackers))
    return total / trials, honest_expect

# 4. Разделение ролей -----------------------------------------------------------
def p_someone_multi_role(N, sizes):
    """Роли заполняются независимым жребием из N без запрета совмещения. Вероятность, что хотя бы один
    человек получил две роли и более (через дополнение — все роли попали в непересекающиеся множества)."""
    p_disjoint = 1.0; used = 0
    for s in sizes:
        p_disjoint *= math.exp(lcomb(N - used, s) - lcomb(N, s)); used += s
    return 1 - p_disjoint

def p_adversary_two_roles(N, b, sizes):
    """Доля недобросовестных b; вероятность, что хотя бы один недобросовестный получил две роли."""
    M = math.ceil(b * N)
    # ожидаемое число недобросовестных с >=2 ролями (верхняя граница вероятности по неравенству Маркова)
    ps = [s / N for s in sizes]
    p_two = 1 - math.prod(1 - p for p in ps) - sum(p * math.prod(1 - q for j, q in enumerate(ps) if j != i) for i, p in enumerate(ps))
    return min(1.0, M * p_two)

# 5. Свежесть статуса -----------------------------------------------------------
def p_accept_forged(C, rule, c, rho):
    """Худший случай: скомпрометированные каналы согласованы; честные показывают свежий статус."""
    if rule == "2 канала":
        return sum(betabin(x, C, c, rho) for x in range(2, C + 1))      # двух согласных подложных достаточно
    maj = C // 2 + 1
    return sum(betabin(x, C, c, rho) for x in range(maj, C + 1))

# 6. Записи дел -----------------------------------------------------------------
def records_conflicts(with_rule):
    f = {n: z3.Bool(n) for n in ["f_request_delete", "f_is_evidence", "f_case_open"]}
    a = {n: z3.Bool(n) for n in ["a_delete", "a_seal", "a_keep_public"]}
    I, And, Not = z3.Implies, z3.And, z3.Not
    rules = {
        "K-16/K-6: просьба удалить персональные данные исполняется": I(f["f_request_delete"], Not(a["a_keep_public"])),
        "K-6: нельзя уничтожать доказательства незавершённого дела": I(And(f["f_is_evidence"], f["f_case_open"]), Not(a["a_delete"])),
        "смысл: исполнить просьбу = удалить": I(And(f["f_request_delete"], Not(a["a_keep_public"])), a["a_delete"]) if not with_rule
            else I(And(f["f_request_delete"], Not(a["a_keep_public"])), z3.Or(a["a_delete"], And(a["a_seal"], f["f_is_evidence"], f["f_case_open"]))),
    }
    bad = 0
    for bits in itertools.product([False, True], repeat=3):
        s = z3.Solver(); s.add(*rules.values(), *[x if b_ else Not(x) for x, b_ in zip(f.values(), bits)])
        bad += s.check() == z3.unsat
    return bad

if __name__ == "__main__":
    if z3 is None:
        print("нужен пакет z3-solver"); sys.exit(1)
    print("=== 1. Единственность продолжения (Z3) ===")
    for n, t in ((17, 9), (17, 8), (7, 4), (7, 3)):
        r = two_disjoint_quorums_possible(n, t)
        print(f"  {t} из {n}: два непересекающихся кворума {'ВОЗМОЖНЫ' if r else 'невозможны (доказано)'}")
    print("=== 2. Тупик набора ключей (перебор состояний) ===")
    for rec in (False, True):
        print(f"  {'с' if rec else 'без'} В-11: тупик {'достижим' if deadlock_reachable(17, 9, rec) else 'недостижим'}")
    print("=== 3. Жребий: среднее число мест противника (3 из 20 участников, 7 мест; честное ожидание 1.05) ===")
    for bc in (False, True):
        m, h = lottery_bias(beacon=bc, trials=4000)
        print(f"  {'с внешним источником (В-12)' if bc else 'без внешнего источника'}: {m:.2f} (честно {h:.2f}, смещение {m / h - 1:+.0%})")
    print("=== 4. Совмещение ролей без запрета (17 держателей, 6 команд по 4 хранителя, 5 подписантов казны) ===")
    for N in (60, 100, 300):
        print(f"  N={N}: хотя бы один человек в нескольких ролях {p_someone_multi_role(N, [17, 24, 5]):.2f}; "
              f"недобросовестный (10%) в двух ролях не более {p_adversary_two_roles(N, 0.10, [17, 24, 5]):.2f}")
    print("=== 5. Свежесть: вероятность принять устаревший статус при откате (каналов 6) ===")
    for c, rho in ((0.05, 0.1), (0.10, 0.3)):
        print(f"  компрометация {c}, общая причина {rho}: правило «2 канала» {p_accept_forged(6, '2 канала', c, rho):.1e}; "
              f"«большинство каналов» {p_accept_forged(6, 'большинство', c, rho):.1e}")
    print("=== 6. Записи дел (Z3) ===")
    print(f"  без правила П-13: противоречивых ситуаций {records_conflicts(False)}; с правилом: {records_conflicts(True)}")
