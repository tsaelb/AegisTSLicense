#!/usr/bin/env python3
"""
AEGIS — Appendix G. Thresholds and parameters that were previously set without a model.
English version of «AEGIS_приложение_пороги_и_параметры.py»; it computes the same numbers.

Status: working material. Prepared with the help of AI according to the instructions of the project owner; requires
independent review. The results hold only within the assumptions listed for each computation (K-10).

Uses functions of Appendices A (review model) and B (governance models) from the same folder.

COMPUTATIONS
  1. F-4: the smallest number of voters — a consequence of R-6 (k vouchers from other voters).
  2. R-7: sample size for a 2.5% bound and probabilities of lowering the level.
  3. P-17: admissible share of reviewers with a mutual tie.
  4. E-5: quorum of the on-call list for irreversible actions.
  5. M-3: treasury signing scheme.
  6. M-4: treasury reserve in months.
  7. F-4: the smallest number of people to satisfy B-1, B-8, U-8 (and M-3) at the same time.
  8. L-10: length of the License identifier (truncated hash).
  9. J-9: sensitivity of the divergence rule to correlation of reviewers' errors.
 10. K-0.14: the order of choice always gives a non-empty answer that cannot be improved on the purposes (exhaustive check).
 11. B-6: how many independent reviewers per area are needed before release and what this guarantees.

RUN
  python3 AEGIS_appendix_G_thresholds_and_parameters.py
"""
import importlib.util, math, os, sys
sys.dont_write_bytecode = True
import random as random_module

HERE = os.path.dirname(os.path.abspath(__file__))

def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

A = _load("AEGIS_appendix_A_review_model.py")
B = _load("AEGIS_appendix_B_governance_models.py")

# ---------- binomial bounds without external libraries ----------
def binom_pmf(x, n, p):
    if p <= 0:
        return 1.0 if x == 0 else 0.0
    if p >= 1:
        return 1.0 if x == n else 0.0
    return math.exp(A.lcomb(n, x) + x * math.log(p) + (n - x) * math.log(1 - p))

def binom_cdf(x, n, p):
    return sum(binom_pmf(i, n, p) for i in range(0, x + 1))

def upper_bound(x, n, alpha=0.05):
    """Exact (Clopper–Pearson) one-sided upper bound of a share with x findings out of n."""
    if x >= n:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if binom_cdf(x, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi

def min_sample(bound, alpha=0.05):
    """The smallest size at which 0 findings give an upper bound not above bound."""
    return math.ceil(math.log(alpha) / math.log(1 - bound))

def p_step_down(n, true_share, bound=0.025):
    """Probability within a year that the bound from a sample of n does not exceed bound."""
    return sum(binom_pmf(x, n, true_share) for x in range(n + 1) if upper_bound(x, n) <= bound)

# ---------- 3. mutual ties in a panel ----------
BASE_GRID = [(rho, q) for rho in (0.03, 0.05, 0.10) for q in (0.05, 0.10, 0.15)]
Q_EXT_MAX = max(A.GRID_EXT["q"])          # 0.20 — the largest share of dishonest reviewers taken into account when choosing n, k
Q_BASE_MAX = max(A.GRID["q"])             # 0.15

def worst_fp_with_ties(s, n=None, k=None):
    """Worst case: tied reviewers vote as one dishonest block (the share s is added to q)."""
    n = n or A.PANEL_N
    k = k or A.PANEL_K
    return max(A.errors(1000, min(q + s, 1.0), n, k, 0.05, 0.10, rho)[0] for rho, q in BASE_GRID)

# ---------- 4–5. t-of-n quorums by the signing model of Appendix B ----------
def robust_t_of_n(grid, forge_norm, unavail_norm, lams=B.SIGN_LAMS, nmax=31):
    """Minimax relative loss, as in B-1: loss = capture/forge_norm + unavailability/unavail_norm + lam*n."""
    cands = [(n, t) for n in range(3, nmax + 1) for t in range(n // 2 + 1, n + 1)]
    L = {}
    for n, t in cands:
        for g in grid:
            u, f = B.signing_risk(n, t, *g)
            L[(n, t, g)] = f / forge_norm + u / unavail_norm
    opt = {(g, la): min(L[(n, t, g)] + la * n for n, t in cands) for g in grid for la in lams}
    return sorted((max((L[(n, t, g)] + la * n) / opt[(g, la)] for g in grid for la in lams), n, t) for n, t in cands)

# On-call list (E-5): l — unavailability within the window of an urgent decision (hours), c — capture or compromise of a participant.
DUTY_GRID = [(l, c, r) for l in (0.2, 0.3, 0.5) for c in (0.02, 0.05, 0.10) for r in (0.02, 0.05, 0.10)]
# Treasury (M-3): an erroneous payment is only partly reversible, a delayed payment is tolerable.
TREASURY_FORGE, TREASURY_UNAVAIL = 1e-3, 1e-2

# ---------- 6. treasury reserve ----------
TREASURY_SCEN = [(0.1, 0.05), (0.2, 0.05), (0.2, 0.1), (0.3, 0.2)]   # (departure of a source l, common cause rho)
RECOVERY_MEANS = (3, 6, 12)                                           # mean income recovery time, months

def reserve_months(p_shock, mu, eps=0.01):
    """Reserve R (months) at which the risk within a year p_shock * P(recovery longer than R) <= eps;
    the recovery time is exponential with mean mu."""
    if p_shock <= eps:
        return 0
    return math.ceil(mu * math.log(p_shock / eps))

# ---------- 7. number of people ----------
def people_needed(holders=17, channels=6, team=4, treasury=0, rotate=False):
    base = holders + channels * team + treasury
    return base + (channels * team if rotate else 0)

# ---------- 10. K-0.14 ----------
def k014_choose(opts):
    """opts: a list of (power, purpose1, purpose2, restriction); power and restriction — less is better, purposes — more is better."""
    pmin = min(o[0] for o in opts)
    s1 = [o for o in opts if o[0] == pmin]
    dom = lambda a, b: (a[1] >= b[1] and a[2] >= b[2]) and (a[1] > b[1] or a[2] > b[2])
    s2 = [o for o in s1 if not any(dom(x, o) for x in s1)]
    rmin = min(o[3] for o in s2)
    return [o for o in s2 if o[3] == rmin]

def k014_check(vals=(0, 1, 2), max_opts=3):
    import itertools as it
    pts = list(it.product(vals, repeat=4))
    count = 0
    for r in range(1, max_opts + 1):
        for opts in it.combinations(pts, r):
            ch = k014_choose(list(opts))
            count += 1
            if not ch:
                return False, count
            pmin = min(o[0] for o in opts)
            for c in ch:
                if c[0] != pmin:
                    return False, count
                if any(o[0] == pmin and o[1] >= c[1] and o[2] >= c[2] and (o[1] > c[1] or o[2] > c[2]) for o in opts):
                    return False, count
    return True, count

# ---------- 11. independent review before release (B-6) ----------
# Errors in the text and the models differ in how noticeable they are: each independent reviewer finds error i with
# probability p_i. It cannot be claimed that there are no errors (K-10). Something else can be guaranteed: if the last
# round of r new reviewers of an area found no new material error, then every remaining
# error with noticeability at least p_min would have survived such a round with probability at most (1 - p_min)^r.
def reviewers_needed(p_min=1/3, alpha=0.05):
    return math.ceil(math.log(alpha) / math.log(1 - p_min))

def survival(p, r):
    return (1 - p) ** r

def chapman_remaining(n1, n2, m):
    """Estimate of the number of errors not found, from two reviewers (capture–recapture, Chapman estimator)."""
    return (n1 + 1) * (n2 + 1) / (m + 1) - 1 - (n1 + n2 - m)

def sim_rounds(D=20, a=1.0, b=2.0, r=8, max_rounds=30, trials=2000, seed=7):
    """Rounds: r new reviewers in each; what is found is fixed; the end is a round without new findings.
    Returns the share of cases where an error with noticeability >= 1/3 remained, and the mean number remaining."""
    rnd = random_module.Random(seed)
    left_easy = left_all = 0
    rounds_total = 0
    for _ in range(trials):
        p = [rnd.betavariate(a, b) for _ in range(D)]
        alive = set(range(D))
        for rd in range(max_rounds):
            found = {i for i in alive if any(rnd.random() < p[i] for _ in range(r))}
            rounds_total += 1
            if not found:
                break
            alive -= found
        left_all += len(alive)
        left_easy += any(p[i] >= 1 / 3 for i in alive)
    return left_easy / trials, left_all / trials, rounds_total / trials

# ---------- 8. hash strength over a long horizon ----------
# Assumptions (K-10):
#  * today an adversary can direct up to W0 = 1e21 hashes/s to a search (the order of the Bitcoin network's power, 2026);
#  * power doubles every Td years; Td = 2 (the former pace), 1, 0.5 and 0.25 (faster than the current growth of
#    computation for AI, about 4–5 times a year) — the exponential continues without saturation (worst case);
#  * an attack succeeds if within one year the available power covers the required work;
#  * quantum adversary: Grover gives 2^(b/2) sequential steps for a preimage, and M machines speed up
#    the search only by sqrt(M); for collisions the Brassard–Høyer–Tapp estimate 2^(b/3) is used (optimistic
#    for the adversary: it requires quantum memory of the same order);
#  * the physical limit for irreversible computation is the Landauer bound kT·ln2 per bit at T = 3 K (cosmic
#    background), the energy is the entire radiation of the Sun over 10^10 years, and one hash counts as one bit
#    operation (generous to the adversary). This limit does not apply to reversible computation — hence a
#    renewal procedure is needed, not only a margin of length.
YEAR = 3.156e7
W0 = 1e21
TDS = (2.0, 1.0, 0.5, 0.25)

def years_until(work_bits, td, w0=W0):
    """In how many years the adversary's annual power will reach 2^work_bits (0 if already)."""
    now = math.log2(w0 * YEAR)
    return max(0.0, td * (work_bits - now))

def landauer_bits(T=3.0, years=1e10, power=3.828e26):
    k = 1.380649e-23
    return math.log2(power * years * YEAR / (k * T * math.log(2)))

def grover_years(bits, machines_log2=80, rate=1e9):
    """A Grover preimage on 2^machines_log2 quantum machines at rate steps/s."""
    return 2.0 ** (bits / 2 - machines_log2 / 2) / rate / YEAR

# Properties: (name, classical work in bits, quantum work in bits)
def strength(out_bits, family):
    return {"second preimage": (out_bits, out_bits / 2), "collision": (out_bits / 2, out_bits / 3)}

HASHES = [("64 bits (truncation)", 64), ("128 bits (truncation)", 128), ("SHA-256 / SHA3-256", 256), ("SHA-512 / SHA3-512", 512)]

# Renewal threshold: the margin (in bits) must cover the growth of power during the renewal time L at the fastest
# pace and a sudden loss of J bits from cryptanalysis. Historically: MD5 — a collision in ~2^18 instead of 2^64
# (a loss of ~46 bits), SHA-1 — ~2^63 instead of 2^80 (a loss of ~17 bits).
def renewal_margin(L=2.0, td_min=min(TDS), J=46, safety=2.0):
    return math.ceil(safety * L / td_min + J)

if __name__ == "__main__":
    print("=== 1. F-4: the smallest number of voters ===")
    ks = [4, 5, 5]
    for lvl, k in enumerate(ks, 1):
        print(f"  level {lvl}: k={k} vouchers from other voters -> at least {k + 1} voters are needed")
    print("  conclusion: the F-4 threshold = k+1; at the initial level — 5 (a logical consequence of R-6, not a provisional number)")

    print("\n=== 2. R-7: sample and lowering of the level ===")
    for b in (0.05, 0.025):
        print(f"  bound {b:.1%} with 0 findings: size at least {min_sample(b)}")
    print(f"  with a size of 59 the smallest reachable bound is {upper_bound(0, 59):.2%} — the 2.5% bound is unreachable")
    n2 = min_sample(0.025)
    for share in (0.005, 0.01, 0.02, 0.05):
        p = p_step_down(n2, share)
        print(f"  size {n2}, true share {share:.1%}: lowering within a year {p:.3f}, two years in a row {p * p:.4f}")
    print("  conclusion: to lower the level the sample is at least 119; false lowering at a 5% share — about 5·10⁻⁶ over two years;")
    print("  lowering is deliberately slower than raising; 2.5% is half of the raising threshold (hysteresis), not the result of optimization")

    print("\n=== 3. P-17: share of reviewers with a mutual tie ===")
    for s in (0.0, 0.05, 0.10):
        print(f"  share {s:.0%}: worst false \"proven\" {worst_fp_with_ties(s):.2e}")
    print(f"  the scheme n={A.PANEL_N}, k={A.PANEL_K} was chosen taking into account a share of dishonest reviewers up to {Q_EXT_MAX:.0%};")
    print(f"  in the base grid up to {Q_BASE_MAX:.0%}; tied reviewers act in the worst case as one block: q + s <= {Q_EXT_MAX:.0%}")
    print(f"  adopted limit: s <= {Q_EXT_MAX - Q_BASE_MAX:.0%} (with n=79 — no more than {math.floor((Q_EXT_MAX - Q_BASE_MAX) * A.PANEL_N + 1e-9)} people)")

    print("\n=== 4. E-5: quorum of the on-call list for irreversible actions ===")
    rk = robust_t_of_n(DUTY_GRID, 1e-3, 1e-2, nmax=21)
    for w, n, t in rk[:4]:
        print(f"  {t} of {n}: worst ratio to the optimum {w:.2f}")
    d = {(n, t): w for w, n, t in rk}
    print(f"  for comparison 2 of 3: {d[(3, 2)]:.1f}")
    for g in [(0.3, 0.05, 0.05), (0.5, 0.10, 0.10)]:
        u3, f3 = B.signing_risk(3, 2, *g); u17, f17 = B.signing_risk(17, 9, *g)
        print(f"  scenario l={g[0]}, c={g[1]}: capture of a quorum of 3 (2 of 3) {f3:.1e}; 9 of 17 {f17:.1e}; unavailability of 9 of 17 {u17:.2f}")
    print(f"  adopted scheme: 9 of 17 — worse than the best option by {d[(17, 9)] / rk[0][0] - 1:.1%} (under 2%, within the model's precision);")
    print("  with practical equality the smaller number of people is chosen (K-8), as in B-1")
    print("  unavailability of the quorum gives no right to act without it: only reversible measures of classes 1–2 are available")

    print("\n=== 5. M-3: treasury signing scheme (capture 1e-3, unavailability 1e-2) ===")
    rk = robust_t_of_n(B.SIGN_GRID, TREASURY_FORGE, TREASURY_UNAVAIL)
    for w, n, t in rk[:3]:
        print(f"  {t} of {n}: worst ratio to the optimum {w:.2f}")
    print(f"  adopted treasury scheme: {rk[0][2]} of {rk[0][1]}")

    print("\n=== 6. M-4: treasury reserve (risk of mandatory expenses stopping within a year <= 1%) ===")
    worst = {}
    for l, r in TREASURY_SCEN:
        p = B.treasury_risk(0.10, 0.30, l, r)
        row = {mu: reserve_months(p, mu) for mu in RECOVERY_MEANS}
        for mu, v in row.items():
            worst[mu] = max(worst.get(mu, 0), v)
        print(f"  departure {l}, common cause {r}: shock within a year {p:.4f}; reserve needed " +
              ", ".join(f"{v} months with recovery ~{mu} months" for mu, v in row.items()))
    print(f"  conclusion: 12 months is the smallest reserve covering the severe scenario with recovery up to 6 months ({worst[6]} months);")
    print(f"  with recovery ~12 months, {worst[12]} months are needed — this is openly acknowledged")

    print("\n=== 7. F-4: number of people with the ban on combining roles (U-8) ===")
    print(f"  release (17 holders + 6 teams of 4 keepers): {people_needed()}")
    tn = rk[0][1]
    print(f"  with a treasury ({tn} signatories): {people_needed(treasury=tn)}")
    print(f"  replacing all keepers after a year without a repeat term: {people_needed(rotate=True)} (with a treasury {people_needed(treasury=tn, rotate=True)})")

    print("\n=== 8. L-10, B-7: hash strength as the computing power of humanity and AI grows ===")
    now = math.log2(W0 * YEAR)
    print(f"  today about 2^{now:.0f} hashes per year are available to an adversary")
    print(f"  physical limit of irreversible computation (Landauer, 3 K, all the Sun's radiation over 10^10 years): 2^{landauer_bits():.0f}")
    for name, b in HASHES:
        st = strength(b, name)
        parts = []
        for prop, (cb, qb) in st.items():
            ys = [years_until(cb, td) for td in TDS]
            over = "above the physical limit" if cb > landauer_bits() else "below the physical limit"
            parts.append(f"{prop}: 2^{cb:.0f} ({over}); years until search at Td=2/1/0.5/0.25: "
                         + "/".join(f"{y:.0f}" for y in ys) + f"; quantum 2^{qb:.0f}")
        print(f"  {name}:")
        for x in parts:
            print("    " + x)
    print(f"  Grover, SHA-512 preimage on 2^80 quantum machines at 1e9 steps/s: ~{grover_years(512):.1e} years; "
          f"SHA-256: ~{grover_years(256):.1e} years")
    M = renewal_margin()
    print(f"  renewal threshold: a margin of at least {M} bits (2 years for renewal with doubling every 0.25 years, x2, plus a jump of 46 bits)")
    for name, b in HASHES:
        cb = b / 2   # collision — the weakest property
        y = min(years_until(cb + M, td) for td in TDS)
        print(f"    {name}: renew no later than in {y:.0f} years at the worst pace (by collision)")
    print("  conclusion: no fixed length is eternal; adopted — full SHA-512 and SHA3-512 (different constructions),")
    print("  collision resistance of 2^256 above the physical limit of irreversible computation, and mandatory renewal")
    print("  of proofs with a new algorithm when the margin falls below the threshold or an attack is published (RFC 4998)")

    print("\n=== 9. J-9: sensitivity to correlation of errors (loss = 20·false restriction + miss) ===")
    wins, total, exc = 0, 0, []
    for rho in (0.05, 0.10, 0.15, 0.20):
        for q in (0.10, 0.20):
            fp, fn = A.errors(1000, q, A.PANEL_N, A.PANEL_K, 0.05, 0.10, rho)
            for c1, c2 in ((0.01, 0.1), (0.05, 0.2), (0.1, 0.3)):
                s7 = 20 * fp + fn
                both = 20 * fp * c1 + (1 - (1 - fn) * (1 - c2))
                court = 20 * c1 + c2
                total += 1
                if s7 <= min(both, court):
                    wins += 1
                else:
                    exc.append((rho, q, c1, c2))
    print(f"  \"follow Section 7\" is no worse than the alternatives in {wins} of {total} scenarios")
    for e in exc:
        print(f"  exception: rho={e[0]}, q={e[1]}, the court errs {e[2]}/{e[3]} — better \"restrict only if both found\"")
    print("  assumption: errors of the court and of the review are independent")

    print("\n=== 10. K-0.14: the order of choice when provisions collide ===")
    ok, cnt = k014_check()
    print(f"  enumeration of all sets of up to 3 options (values 0–2 on four attributes, {cnt} sets): "
          + ("the answer is always non-empty, gives no extra power and cannot be improved on both purposes" if ok else "COUNTEREXAMPLE FOUND"))
    print("  general proof: a finite non-empty set has a minimum in power; among the minimal ones there are")
    print("  those that cannot be improved on the purposes (Pareto optimum); among them there is a minimum in restriction")
    bad = [(0, 2, 0, 2), (0, 0, 2, 0), (0, 1, 1, 1)]
    print("  control: the former rule \"best on the purposes and least restrictive\" for options", bad,
          "— none is best on both purposes and restriction at once: there is no answer")

    print("\n=== 11. B-6: independent review before release ===")
    r = reviewers_needed()
    print(f"  a round without new findings of r = {r} new reviewers: an error with noticeability >= 1/3 survives it with probability "
          f"{survival(1/3, r):.3f} (<= 5%)")
    for pm in (0.5, 0.2, 0.1):
        print(f"    for comparison: noticeability {pm}: survives with probability {survival(pm, r):.2f}")
    print(f"  Chapman estimate (example: reviewers found 12 and 10, 6 in common): about {chapman_remaining(12, 10, 6):.1f} not found")
    for a, b in ((1, 1), (1, 2), (0.5, 1.5)):
        e, al, rd = sim_rounds(a=a, b=b, r=r)
        print(f"  simulation, noticeability Beta({a},{b}), 20 errors: a noticeable one (>=1/3) remained — {e:.3f}; "
              f"on average {al:.2f} remained (mostly hard to notice); rounds on average {rd:.1f}")
    print("  conclusion: for each area — rounds of review until a round of 8 new independent reviewers without new")
    print("  material findings; the guarantee is only for noticeable errors, hard-to-notice ones are possible — this is openly acknowledged")
