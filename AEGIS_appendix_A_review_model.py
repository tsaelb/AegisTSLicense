#!/usr/bin/env python3
"""
AEGIS — Appendix A to the section "Independent review and protective measures".
A mathematical model for choosing the number of reviewers n and the decision threshold k.
English version of «AEGIS_приложение_модель_проверки.py»; it computes the same numbers.

Status: working material. The model was prepared with the help of AI according to the instructions of the project
owner and requires independent review by a statistician. The results hold only within the assumptions listed
below; this is not a claim of truth or infallibility (K-10).

MODEL
  N   — size of the pool of admitted reviewers;
  q   — upper estimate of the share of dishonest reviewers in the pool; worst case: they always vote
        for the wrong outcome;
  e   — mean probability that an honest reviewer sees a violation where there is none;
  m   — mean probability that an honest reviewer misses a real violation;
  rho — intra-class correlation of honest reviewers' errors (shared premises, mutual influence):
        the probability of error in a case p ~ Beta with mean e (or m) and correlation rho;
  n   — number of reviewers, selected at random without replacement (hypergeometric distribution);
  k   — minimum number of "violation" votes for the finding "violation proven".

  FP(n,k) — probability of the finding "proven" when there is no violation;
  FN(n,k) — probability of the finding "not proven" when there is a violation.

CHOICE OF PARAMETERS (robust criterion)
  Loss per case: L = R*(1-pi)*FP + pi*FN + lam*n,
    R  — how many times a false "proven" is worse than a missed violation;
    pi — share of substantiated reports among those reaching full review;
    lam — cost of one reviewer in units of a "missed violation".
  The unknowns (rho, R, pi, q) are enumerated over a grid of plausible values.
  The (n,k) chosen minimizes the largest ratio over scenarios L / L_opt(scenario)
  (minimax relative loss).

ASSUMPTIONS AND LIMITS
  * the panel is really selected at random, votes are counted honestly;
  * the outcome is binary ("proven" / "not proven"); the status "undetermined" is not modelled separately;
  * the quality of evidence is not modelled;
  * e, m, rho, q are initial estimates until data appear; they must be estimated from the audit (P-16);
  * q cannot be measured, only bounded from above.

RUN (numpy and scipy are needed for the extended choice and the small community)
  python3 AEGIS_appendix_A_review_model.py            # computation, check, robust choice
  python3 AEGIS_appendix_A_review_model.py --quick    # without the Monte Carlo simulation
  python3 AEGIS_appendix_A_review_model.py --quick --small  # plus the computation for a small community (P-15)
"""
import itertools, math, sys

# ---------- distributions ----------
def lcomb(a, b):
    return math.lgamma(a + 1) - math.lgamma(b + 1) - math.lgamma(a - b + 1) if 0 <= b <= a else -math.inf

def hyper(j, N, M, n):
    """P(exactly j dishonest reviewers on the panel) when choosing n of N without replacement, M dishonest."""
    return math.exp(lcomb(M, j) + lcomb(N - M, n - j) - lcomb(N, n))

def lbeta(a, b):
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)

def betabin(x, n, mean, rho):
    """Beta-binomial probability of x "erroneous" votes out of n with mean mean and correlation rho."""
    if rho <= 0:
        return math.exp(lcomb(n, x) + x * math.log(mean) + (n - x) * math.log(1 - mean))
    a = mean * (1 - rho) / rho
    b = (1 - mean) * (1 - rho) / rho
    return math.exp(lcomb(n, x) + lbeta(x + a, n - x + b) - lbeta(a, b))

# ---------- errors of the scheme ----------
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
    """Threshold rule: at least 60% of votes, rounded up."""
    return math.ceil(0.6 * n)

# ---------- robust choice ----------
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


# ---------- extended robust choice (vectorized computation; numpy and scipy are needed) ----------
GRID_EXT = {"rho": [0.03, 0.05, 0.10, 0.15, 0.20], "q": [0.05, 0.10, 0.15, 0.20],
            "e": [0.03, 0.05, 0.08], "m": [0.05, 0.10, 0.15],
            "R": [10, 30, 100], "pi": [0.2, 0.5], "lam": [0.0002, 0.0005, 0.002]}

def _np():
    import numpy as np
    from scipy.special import gammaln, betaln
    return np, gammaln, betaln

def errors_all_k(N, q, n, e, m, rho, ceil_bad=False):
    """FP[k], FN[k] for all k at once. Matches errors() (checked in self_check)."""
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
    """Minimax relative loss over the extended grid (q up to 0.20, rho up to 0.20, spread of e, m, R, pi, lam).
    Returns a list (worst ratio to the optimum, n, k), sorted in ascending order."""
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

PANEL_N, PANEL_K = 79, 51      # adopted panel (P-3b, P-7) by robust_choice_ext

# ---------- small community (P-15) ----------
def errors_small(N, q, n, k, e, m, rho):
    """Like errors, but the number of dishonest reviewers is rounded up: with a small N at least one (worst case)."""
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
    """Bound on false "proven" for a small community: the worst value of the adopted full scheme over the base grid."""
    return float(_worst_all_k(1000, PANEL_N)[0][PANEL_K])

def small_community(N, bound=None):
    """The best panel (n, k) for a pool of N reviewers: false "proven" in the worst scenario no higher than bound
    (by default — as for the adopted full scheme), and after the panel is chosen N-n reviewers remain from whom
    an appeal panel with the same guarantee can be formed (P-11).
    Returns (n, k, false "proven", miss) or None — then rights are not restricted."""
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
    """The smallest N from which a protective measure is permitted for any larger N (up to Nmax)."""
    feas = [N for N in range(2, Nmax + 1) if small_community(N, bound)]
    for N in feas:
        if all(M in feas for M in range(N, Nmax + 1)):
            return N
    return None

# ---------- check of the formulas ----------
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
    print("Internal checks of the distributions:", "passed" if ok else "FAILED")
    if quick:
        return ok
    try:
        import numpy as np
    except ImportError:
        print("numpy is not installed — simulation skipped"); return ok
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
        print(f"Monte Carlo n={n} k={k}: FP {fp:.5f} / {fp_mc:.5f}, FN {fn:.4f} / {fn_mc:.4f} —", "matches" if good else "DIVERGENCE")
    return ok

if __name__ == "__main__":
    quick = "--quick" in sys.argv
    self_check(quick)
    ranked, worst = robust_choice()
    print("\nRobust choice (minimax relative loss), best options:")
    for w, n, k in ranked[:5]:
        print(f"  n={n} k={k} ({k/n:.0%}): in the worst scenario worse than the optimum by {w:.2f} times")
    for n, k in [(3, 2), (9, 6), (13, 9)]:
        print(f"  for comparison n={n} k={k}: {worst(n, k):.1f} times")
    print("\n(The base grid above is for comparison with the former choice n=29, k=18.)")
    ext = robust_choice_ext()
    print("Extended grid (q up to 0.20, rho up to 0.20, spread of e, m, R, pi, lam), best options:")
    for w, n, k in ext[:5]:
        print(f"  n={n} k={k} ({k/n:.0%}): worst ratio to the optimum {w:.2f}")
    d = {(n, k): w for w, n, k in ext}
    print(f"  for comparison n=29 k=18: {d[(29, 18)]:.2f}; n=65 k=42: {d[(65, 42)]:.2f}")
    n, k = PANEL_N, PANEL_K
    print(f"\nAdopted scheme: n={n}, k={k} — the best option over the extended grid")
    fp, fn = errors(1000, 0.10, n, k, 0.05, 0.10, 0.05)
    print(f"At q=0.10, rho=0.05: P(false \"proven\")={fp:.1e}, P(false \"not proven\")={fn:.3f}")
    print("Note: at rho=0.20 the worst false \"proven\" is about 1.2·10⁻² almost regardless of n — shared premises")
    print("of reviewers are not removed by numbers, only by independence of judgement (P-3c, definition 21).")
    # preliminary screening by 5 reviewers, then with >=2 votes "there are grounds"
    fpp, fnp = errors(1000, 0.10, 5, 2, 0.05, 0.10, 0.05)
    for pi0 in [0.05, 0.20]:
        pi1 = pi0 * (1 - fnp) / (pi0 * (1 - fnp) + (1 - pi0) * fpp)
        share = (1 - pi1) * fp / ((1 - pi1) * fp + pi1 * (1 - fn))
        print(f"Screening 5/2 with a share of substantiated reports {pi0:.0%}: {pi0*(1-fnp)+(1-pi0)*fpp:.0%} of cases reach full review, "
              f"innocent among \"proven\" {share:.3%}, real ones screened out {fnp:.1%}")
    if "--small" in sys.argv:
        bound = small_bound()
        print(f"\nSmall community (P-15): bound on false \"proven\" {bound:.2e} (as for the adopted scheme n={PANEL_N}, k={PANEL_K}, base grid)")
        for N in (10, 12, 13, 14, 20, 30, 40, 60):
            r = small_community(N, bound)
            print(f"  N={N}: " + (f"panel n={r[0]} k={r[1]}, false \"proven\" {r[2]:.1e}, miss {r[3]:.2f}" if r
                                   else "bound unreachable with an appeal — only open measures"))
        print(f"  smallest N from which a measure is permitted for any larger N: {min_community(bound)}")
    print("\nAudit size to estimate an error rate of ~5% with precision ±2% (95%):", math.ceil(1.96 ** 2 * 0.05 * 0.95 / 0.02 ** 2), "votes")
