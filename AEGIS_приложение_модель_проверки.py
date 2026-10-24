#!/usr/bin/env python3
"""
AEGIS — Приложение к разделу «Независимая проверка и защитные меры».
Математическая модель выбора числа проверяющих n и порога решения k.

Статус: рабочий материал. Модель подготовлена с помощью ИИ по указаниям владельца проекта
и требует независимой проверки специалистом по статистике. Результаты верны только в пределах
допущений, перечисленных ниже; это не утверждение об истине или безошибочности (K-10).

МОДЕЛЬ
  N   — размер списка допущенных проверяющих;
  q   — верхняя оценка доли недобросовестных в списке; худший случай: они всегда голосуют
        за неверный исход;
  e   — средняя вероятность, что добросовестный проверяющий увидит нарушение там, где его нет;
  m   — средняя вероятность, что добросовестный проверяющий пропустит настоящее нарушение;
  rho — внутриклассовая корреляция ошибок добросовестных (общие предпосылки, взаимное влияние):
        вероятность ошибки в деле p ~ Beta со средним e (или m) и корреляцией rho;
  n   — число проверяющих, выбираемых случайно без возвращения (гипергеометрическое распределение);
  k   — минимальное число голосов «нарушение» для вывода «нарушение доказано».

  FP(n,k) — вероятность вывода «доказано», когда нарушения нет;
  FN(n,k) — вероятность вывода «не доказано», когда нарушение есть.

ВЫБОР ПАРАМЕТРОВ (устойчивый критерий)
  Потеря на дело: L = R*(1-pi)*FP + pi*FN + lam*n,
    R  — во сколько раз ложное «доказано» хуже пропуска нарушения;
    pi — доля обоснованных сообщений среди дошедших до полной проверки;
    lam — стоимость одного проверяющего в единицах «пропущенного нарушения».
  Неизвестные (rho, R, pi, q) перебираются по сетке правдоподобных значений.
  Выбирается (n,k), минимизирующее наибольшее по сценариям отношение L / L_opt(сценарий)
  (минимакс относительной потери).

ДОПУЩЕНИЯ И ПРЕДЕЛЫ
  * выбор состава действительно случаен, голоса подсчитываются честно;
  * исход бинарный («доказано» / «не доказано»); статус «не установлено» не моделируется отдельно;
  * качество доказательств не моделируется;
  * e, m, rho, q до появления данных — начальные оценки; их нужно оценивать по аудиту (П-16);
  * q невозможно измерить, только оценить сверху.

ЗАПУСК (нужны numpy и scipy для расширенного выбора и малого сообщества)
  python3 AEGIS_приложение_модель_проверки.py            # расчёт, проверка, устойчивый выбор
  python3 AEGIS_приложение_модель_проверки.py --quick    # без симуляции Монте-Карло
  python3 AEGIS_приложение_модель_проверки.py --quick --small  # плюс расчёт для малого сообщества (П-15)
"""
import itertools, math, sys

# ---------- распределения ----------
def lcomb(a, b):
    return math.lgamma(a + 1) - math.lgamma(b + 1) - math.lgamma(a - b + 1) if 0 <= b <= a else -math.inf

def hyper(j, N, M, n):
    """P(в составе ровно j недобросовестных) при выборе n из N без возвращения, M недобросовестных."""
    return math.exp(lcomb(M, j) + lcomb(N - M, n - j) - lcomb(N, n))

def lbeta(a, b):
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)

def betabin(x, n, mean, rho):
    """Бета-биномиальная вероятность x «ошибочных» голосов из n при среднем mean и корреляции rho."""
    if rho <= 0:
        return math.exp(lcomb(n, x) + x * math.log(mean) + (n - x) * math.log(1 - mean))
    a = mean * (1 - rho) / rho
    b = (1 - mean) * (1 - rho) / rho
    return math.exp(lcomb(n, x) + lbeta(x + a, n - x + b) - lbeta(a, b))

# ---------- ошибки схемы ----------
def errors(N, q, n, k, e, m, rho):
    M = int(q * N)
    fp = fn = 0.0
    for j in range(0, min(M, n) + 1):
        h = hyper(j, N, M, n)
        if h == 0:
            continue
        hon = n - j
        fp += h * sum(betabin(x, hon, e, rho) for x in range(hon + 1) if j + x >= k)
        fn += h * sum(betabin(x, hon, 1 - m, rho) for x in range(hon + 1) if x < k)
    return fp, fn

def threshold(n):
    """Правило порога: не менее 60% голосов, округление вверх."""
    return math.ceil(0.6 * n)

# ---------- устойчивый выбор ----------
GRID = {"rho": [0.03, 0.05, 0.10], "R": [10, 30, 100], "pi": [0.2, 0.5], "q": [0.05, 0.10, 0.15]}

def robust_choice(N=1000, e=0.05, m=0.10, lam=0.0005, nmin=9, nmax=49):
    scen = list(itertools.product(GRID["rho"], GRID["R"], GRID["pi"], GRID["q"]))
    cands = [(n, k) for n in range(nmin, min(nmax, N) + 1, 2) for k in range(n // 2 + 1, n + 1)]
    cache = {}
    def E(q, n, k, rho):
        key = (q, n, k, rho)
        if key not in cache:
            cache[key] = errors(N, q, n, k, e, m, rho)
        return cache[key]
    def L(n, k, s):
        rho, R, pi, q = s
        fp, fn = E(q, n, k, rho)
        return R * (1 - pi) * fp + pi * fn + lam * n
    opt = {s: min(L(n, k, s) for n, k in cands) for s in scen}
    ranked = sorted((max(L(n, k, s) / opt[s] for s in scen), n, k) for n, k in cands)
    return ranked, (lambda n, k: max(L(n, k, s) / opt[s] for s in scen))


# ---------- расширенный устойчивый выбор (векторный расчёт; нужны numpy и scipy) ----------
GRID_EXT = {"rho": [0.03, 0.05, 0.10, 0.15, 0.20], "q": [0.05, 0.10, 0.15, 0.20],
            "e": [0.03, 0.05, 0.08], "m": [0.05, 0.10, 0.15],
            "R": [10, 30, 100], "pi": [0.2, 0.5], "lam": [0.0002, 0.0005, 0.002]}

def _np():
    import numpy as np
    from scipy.special import gammaln, betaln
    return np, gammaln, betaln

def errors_all_k(N, q, n, e, m, rho, ceil_bad=False):
    """FP[k], FN[k] для всех k сразу. Совпадает с errors() (проверяется в self_check)."""
    np, gammaln, betaln = _np()
    M = min(N, math.ceil(q * N)) if ceil_bad else int(q * N)
    lc = lambda a, b: gammaln(a + 1) - gammaln(b + 1) - gammaln(a - b + 1)
    j = np.arange(0, min(M, n) + 1); ok = (n - j) <= (N - M)
    hv = np.zeros(len(j)); hv[ok] = np.exp(lc(M, j[ok]) + lc(N - M, n - j[ok]) - lc(N, n))
    def bb(h, mean):
        if h == 0: return np.array([1.0])
        x = np.arange(h + 1); a = mean * (1 - rho) / rho; b = (1 - mean) * (1 - rho) / rho
        return np.exp(lc(h, x) + betaln(x + a, h - x + b) - betaln(a, b))
    pv_no = np.zeros(n + 1); pv_yes = np.zeros(n + 1)
    for jj, h in enumerate(hv):
        if h == 0: continue
        hon = n - jj
        pv_no[jj:jj + hon + 1] += h * bb(hon, e)
        pv_yes[0:hon + 1] += h * bb(hon, 1 - m)
    FP = np.concatenate([np.cumsum(pv_no[::-1])[::-1], [0.0]])
    FN = np.concatenate([[0.0], np.cumsum(pv_yes)])
    return FP, FN

def robust_choice_ext(N=1000, nmin=9, nmax=101):
    """Минимакс относительной потери по расширенной сетке (q до 0,20, rho до 0,20, разброс e, m, R, pi, lam).
    Возвращает список (худшее отношение к оптимуму, n, k), отсортированный по возрастанию."""
    np, _, _ = _np()
    keys = list(itertools.product(GRID_EXT["q"], GRID_EXT["rho"], GRID_EXT["e"], GRID_EXT["m"]))
    ns = list(range(nmin, nmax + 1, 2))
    E = {(n, key): errors_all_k(N, key[0], n, key[2], key[3], key[1]) for n in ns for key in keys}
    scen = list(itertools.product(keys, GRID_EXT["R"], GRID_EXT["pi"], GRID_EXT["lam"]))
    L = {}; best = {}
    for sc in scen:
        key, R, pi, lam = sc; mn = math.inf
        for n in ns:
            FP, FN = E[(n, key)]; ks = np.arange(n // 2 + 1, n + 1)
            L[(sc, n)] = R * (1 - pi) * FP[ks] + pi * FN[ks] + lam * n; mn = min(mn, L[(sc, n)].min())
        best[sc] = mn
    out = []
    for n in ns:
        ks = np.arange(n // 2 + 1, n + 1); ratio = np.zeros(len(ks))
        for sc in scen:
            ratio = np.maximum(ratio, L[(sc, n)] / best[sc])
        out += [(float(r), n, int(k)) for k, r in zip(ks, ratio)]
    return sorted(out)

PANEL_N, PANEL_K = 79, 51      # принятый состав (П-3б, П-7) по robust_choice_ext

# ---------- малое сообщество (П-15) ----------
def errors_small(N, q, n, k, e, m, rho):
    """Как errors, но число недобросовестных округляется вверх: при малом N хотя бы один (худший случай)."""
    M = min(N, math.ceil(q * N))
    fp = fn = 0.0
    for j in range(0, min(M, n) + 1):
        h = hyper(j, N, M, n)
        if h == 0:
            continue
        hon = n - j
        fp += h * sum(betabin(x, hon, e, rho) for x in range(hon + 1) if j + x >= k)
        fn += h * sum(betabin(x, hon, 1 - m, rho) for x in range(hon + 1) if x < k)
    return fp, fn

SMALL_SCEN = list(itertools.product([0.03, 0.05, 0.10], [0.05, 0.10, 0.15]))   # (rho, q)

def worst_errors(N, n, k, e=0.05, m=0.10):
    r = [errors_small(N, q, n, k, e, m, rho) for rho, q in SMALL_SCEN]
    return max(a for a, _ in r), max(b for _, b in r)

def _worst_all_k(N, n, e=0.05, m=0.10):
    np, _, _ = _np()
    F = [errors_all_k(N, q, n, e, m, rho, ceil_bad=True) for rho, q in SMALL_SCEN]
    return np.max([f[0] for f in F], axis=0), np.max([f[1] for f in F], axis=0)

def small_bound():
    """Граница ложного «доказано» для малого сообщества: худшее значение принятой полной схемы по базовой сетке."""
    return float(_worst_all_k(1000, PANEL_N)[0][PANEL_K])

def small_community(N, bound=None):
    """Лучший состав (n, k) для списка из N проверяющих: ложное «доказано» в худшем сценарии не выше bound
    (по умолчанию — как у принятой полной схемы), и после выбора состава остаётся N-n проверяющих, из которых
    можно составить апелляционный состав с той же гарантией (П-11).
    Возвращает (n, k, ложное «доказано», пропуск) или None — тогда права не ограничиваются."""
    if bound is None:
        bound = small_bound()
    def best(pool, nmax):
        out = None
        for n in range(1, min(pool, nmax) + 1):
            fp, fnr = _worst_all_k(pool, n)
            for k in range(n // 2 + 1, n + 1):
                if fp[k] <= bound and (out is None or fnr[k] < out[3]):
                    out = (n, k, float(fp[k]), float(fnr[k]))
        return out
    for nmax in range(N // 2, 0, -1):
        first = best(N, nmax)
        if first and best(N - first[0], first[0]):
            return first
    return None

def min_community(bound=None, Nmax=40):
    """Наименьшее N, начиная с которого защитная мера допустима при любом большем N (до Nmax)."""
    feas = [N for N in range(2, Nmax + 1) if small_community(N, bound)]
    for N in feas:
        if all(M in feas for M in range(N, Nmax + 1)):
            return N
    return None

# ---------- проверка формул ----------
def self_check(quick=False):
    ok = True
    for N, M, n in [(60, 6, 13), (1000, 100, 31)]:
        s = sum(hyper(j, N, M, n) for j in range(0, min(M, n) + 1))
        ok &= abs(s - 1) < 1e-9
    for n, mu, rho in [(13, 0.05, 0.1), (31, 0.9, 0.05)]:
        p = [betabin(x, n, mu, rho) for x in range(n + 1)]
        mean = sum(x * px for x, px in enumerate(p))
        var = sum((x - mean) ** 2 * px for x, px in enumerate(p))
        ok &= abs(sum(p) - 1) < 1e-9 and abs(mean - n * mu) < 1e-6 and abs(var - n * mu * (1 - mu) * (1 + (n - 1) * rho)) < 1e-6
    try:
        for case in [(1000, 0.10, 29, 18, 0.05, 0.10, 0.05), (1000, 0.15, 31, 20, 0.08, 0.15, 0.2)]:
            N, q, n, k, e, m, rho = case
            FP, FN = errors_all_k(N, q, n, e, m, rho); fp, fn = errors(*case)
            ok &= abs(FP[k] - fp) < 1e-12 and abs(FN[k] - fn) < 1e-12
    except ImportError:
        pass
    print("Внутренние проверки распределений:", "пройдены" if ok else "НЕ ПРОЙДЕНЫ")
    if quick:
        return ok
    try:
        import numpy as np
    except ImportError:
        print("numpy не установлен — симуляция пропущена"); return ok
    rng = np.random.default_rng(20261023); T = 400_000
    for case in [(1000, 0.10, 29, 18, 0.05, 0.10, 0.05), (1000, 0.10, 3, 2, 0.05, 0.10, 0.10)]:
        N, q, n, k, e, m, rho = case
        M = int(q * N)
        j = rng.hypergeometric(M, N - M, n, size=T)
        def pd(mu):
            a = mu * (1 - rho) / rho; b = (1 - mu) * (1 - rho) / rho
            return rng.beta(a, b, size=T)
        fp_mc = ((j + rng.binomial(n - j, pd(e))) >= k).mean()
        fn_mc = (rng.binomial(n - j, pd(1 - m)) < k).mean()
        fp, fn = errors(*case)
        tol_fp = 1.96 * math.sqrt(max(fp * (1 - fp), 1e-12) / T) * 1.5 + 1e-5
        tol_fn = 1.96 * math.sqrt(fn * (1 - fn) / T) * 1.5
        good = abs(fp - fp_mc) <= tol_fp and abs(fn - fn_mc) <= tol_fn
        ok &= good
        print(f"Монте-Карло n={n} k={k}: FP {fp:.5f} / {fp_mc:.5f}, FN {fn:.4f} / {fn_mc:.4f} —", "совпадает" if good else "РАСХОЖДЕНИЕ")
    return ok

if __name__ == "__main__":
    quick = "--quick" in sys.argv
    self_check(quick)
    ranked, worst = robust_choice()
    print("\nУстойчивый выбор (минимакс относительной потери), лучшие варианты:")
    for w, n, k in ranked[:5]:
        print(f"  n={n} k={k} ({k/n:.0%}): в худшем сценарии хуже оптимума в {w:.2f} раза")
    for n, k in [(3, 2), (9, 6), (13, 9)]:
        print(f"  для сравнения n={n} k={k}: в {worst(n, k):.1f} раза")
    print("\n(Базовая сетка выше — для сравнения с прежним выбором n=29, k=18.)")
    ext = robust_choice_ext()
    print("Расширенная сетка (q до 0,20, rho до 0,20, разброс e, m, R, pi, lam), лучшие варианты:")
    for w, n, k in ext[:5]:
        print(f"  n={n} k={k} ({k/n:.0%}): худшее отношение к оптимуму {w:.2f}")
    d = {(n, k): w for w, n, k in ext}
    print(f"  для сравнения n=29 k=18: {d[(29, 18)]:.2f}; n=65 k=42: {d[(65, 42)]:.2f}")
    n, k = PANEL_N, PANEL_K
    print(f"\nПринятая схема: n={n}, k={k} — лучший вариант по расширенной сетке")
    fp, fn = errors(1000, 0.10, n, k, 0.05, 0.10, 0.05)
    print(f"При q=0.10, rho=0.05: P(ложно «доказано»)={fp:.1e}, P(ложно «не доказано»)={fn:.3f}")
    print("Замечание: при rho=0,20 худшее ложное «доказано» около 1,2·10⁻² почти не зависит от n — общие предпосылки")
    print("проверяющих не устраняются числом, только независимостью суждений (П-3в, определение 21).")
    # предварительный отбор 5 проверяющими, дальше при >=2 голосах «есть основания»
    fpp, fnp = errors(1000, 0.10, 5, 2, 0.05, 0.10, 0.05)
    for pi0 in [0.05, 0.20]:
        pi1 = pi0 * (1 - fnp) / (pi0 * (1 - fnp) + (1 - pi0) * fpp)
        share = (1 - pi1) * fp / ((1 - pi1) * fp + pi1 * (1 - fn))
        print(f"Отбор 5/2 при доле обоснованных {pi0:.0%}: до полной проверки доходит {pi0*(1-fnp)+(1-pi0)*fpp:.0%} дел, "
              f"невиновных среди «доказано» {share:.3%}, отсеяно настоящих {fnp:.1%}")
    if "--small" in sys.argv:
        bound = small_bound()
        print(f"\nМалое сообщество (П-15): граница ложного «доказано» {bound:.2e} (как у принятой схемы n={PANEL_N}, k={PANEL_K}, базовая сетка)")
        for N in (10, 12, 13, 14, 20, 30, 40, 60):
            r = small_community(N, bound)
            print(f"  N={N}: " + (f"состав n={r[0]} k={r[1]}, ложно «доказано» {r[2]:.1e}, пропуск {r[3]:.2f}" if r
                                   else "граница недостижима с апелляцией — только открытые меры"))
        print(f"  наименьшее N, начиная с которого мера допустима при любом большем N: {min_community(bound)}")
    print("\nОбъём аудита для оценки частоты ошибок ~5% с точностью ±2% (95%):", math.ceil(1.96 ** 2 * 0.05 * 0.95 / 0.02 ** 2), "голосов")
