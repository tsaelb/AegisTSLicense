#!/usr/bin/env python3
"""
AEGIS — Appendix B to the sections "Decision procedure" (R) and "Release, signing, channels" (B).
Models: peer decisions, fake pseudonyms and admission to vote; t-of-n release signing; distribution channels; treasury; channel keepers; patent deterrence.
English version of «AEGIS_приложение_модели_управления.py»; it computes the same numbers.

Status: working material. Prepared with the help of AI according to the instructions of the project owner; requires
independent review. The results hold only within the listed assumptions (K-10).

RUN:  python3 AEGIS_appendix_B_governance_models.py
"""
import math

def lcomb(a, b):
    return math.lgamma(a + 1) - math.lgamma(b + 1) - math.lgamma(a - b + 1) if 0 <= b <= a else -math.inf

def betabin(x, n, mean, rho):
    """Beta-binomial distribution: x "events" out of n with mean mean and intra-class correlation rho."""
    if n == 0:
        return 1.0 if x == 0 else 0.0
    if rho <= 0:
        return math.exp(lcomb(n, x) + (x * math.log(mean) if x else 0) + ((n - x) * math.log(1 - mean) if n - x else 0))
    a = mean * (1 - rho) / rho; b = (1 - mean) * (1 - rho) / rho
    lb = lambda u, v: math.lgamma(u) + math.lgamma(v) - math.lgamma(u + v)
    return math.exp(lcomb(n, x) + lb(x + a, n - x + b) - lb(a, b))

# ---------------------------------------------------------------------------
# 1. PEER DECISIONS (Section R)
# V voters; a share b is a coordinated block that always votes for harm.
# Honest voters turn out with probability t and vote correctly with probability ~p (correlation rho).
# Rule R-3: adopt if "for" > tau of those voting AND "for" >= phi of all V.
# ---------------------------------------------------------------------------
def decision_errors(V, b, t, p, rho, tau=0.5, phi=0.20):
    B = round(b * V); H = V - B; harmful = blocked = 0.0
    for h in range(H + 1):
        ph = math.exp(lcomb(H, h) + (h * math.log(t) if h else 0) + ((H - h) * math.log(1 - t) if H - h else 0))
        if ph < 1e-15:
            continue
        n = B + h
        for x in range(h + 1):          # harmful: the block votes "for", honest voters "for" by mistake
            yes = B + x
            if yes > tau * n and yes >= phi * V:
                harmful += ph * betabin(x, h, 1 - p, rho)
        for x in range(h + 1):          # useful: the block votes "against", honest voters "for" correctly
            yes = x
            if not (yes > tau * n and yes >= phi * V):
                blocked += ph * betabin(x, h, p, rho)
    return harmful, blocked

def theorem_window(b, p):
    """Theorem (V->inf, rho=0, full turnout): admissible tau lie in (b+(1-b)(1-p), (1-b)p);
    the window is non-empty if and only if b < (2p-1)/(2p)."""
    return b + (1 - b) * (1 - p), (1 - b) * p, (2 * p - 1) / (2 * p)


def sybil_effective_block(b, s):
    """Fake pseudonyms (Sybil attack). b — share of the coordinated block among real people;
    s — share of fake pseudonyms among all those entitled to vote (all of them vote with the block).
    Effective block share b' = b(1-s) + s. Decisions are robust (theorem) while b' < (2p-1)/(2p)."""
    return b * (1 - s) + s

def sybil_max_share(b, p):
    """The largest share of fake pseudonyms at which the threshold window is still non-empty."""
    lim = (2 * p - 1) / (2 * p)
    return max(0.0, (lim - b) / (1 - b))

def decision_errors_sybil(V, b, s, t, p, rho, tau=0.5, phi=0.20):
    """V — number of real people; fakes S = s/(1-s)*V are added to the block and to the denominator of phi."""
    S = round(s / (1 - s) * V)
    return decision_errors(V + S, (round(b * V) + S) / (V + S), t, p, rho, tau, phi)


# ---------------------------------------------------------------------------
# 1b. ADMISSION TO VOTE (R-6, R-7): window of W months, at least m months with a contribution, k vouchers by lot
# Honest: monthly activity a ~ Beta(A,B). Adversary: budget of beta*V accepted contributions per month;
# a fake contribution is exposed at acceptance with prob. delta. A voucher by lot is fake with prob. s,
# an honest one is deceived with prob. f. The share of fakes s* is a fixed point.
# Conclusion of the model: an activity requirement does not push the share of fakes below ~beta/q; vouching by lot decides.
# ---------------------------------------------------------------------------
def _beta_w(a, A, B):
    return math.exp((A - 1) * math.log(a) + (B - 1) * math.log(1 - a)
                    - (math.lgamma(A) + math.lgamma(B) - math.lgamma(A + B)))

def _below(W, m, a):
    return sum(math.comb(W, j) * a ** j * (1 - a) ** (W - j) for j in range(m))

def honest_exclusion(W, m, A=2.0, B=3.0, a0=0.25, grid=400):
    """Share of steady honest participants (activity a >= a0) who do not get a vote."""
    pts = [a0 + (1 - a0) * (i + 0.5) / grid for i in range(grid)]
    w = [_beta_w(a, A, B) for a in pts]
    return sum(wi * _below(W, m, a) for wi, a in zip(w, pts)) / sum(w)

def honest_voting_share(W, m, A=2.0, B=3.0, grid=400):
    return sum(_beta_w((i + .5) / grid, A, B) * (1 - _below(W, m, (i + .5) / grid)) for i in range(grid)) / grid

def sybil_fixed_point(W, m, k, beta, delta, f, q):
    cand = beta * W / m * (1 - delta) ** m
    s = 0.0
    for _ in range(1000):
        S = cand * (s + (1 - s) * f) ** k
        s_new = S / (q + S)
        if abs(s_new - s) < 1e-12:
            break
        s = s_new
    return s

def admission_levels(target=0.05):
    """For each scenario (beta, f) — the rule with the least exclusion of honest participants with s* <= target."""
    cfg = [(W, m, honest_voting_share(W, m), honest_exclusion(W, m)) for W in (6, 12, 24) for m in range(1, W + 1)]
    out = []
    for beta in (0.02, 0.05, 0.10):
        for f in (0.3, 0.6, 0.9):
            best = None
            for W, m, q, e in cfg:
                for k in range(1, 6):
                    sv = sybil_fixed_point(W, m, k, beta, 0.05, f, q)
                    if sv <= target and (best is None or (e, k, W) < best[0]):
                        best = ((e, k, W), W, m, k, sv)
            out.append((beta, f, best))
    return out

# ---------------------------------------------------------------------------
# 2. RELEASE SIGNING t OF n (B-1)
# Over a rotation period a key is lost with probability l, compromised with probability c; common cause rho.
# ---------------------------------------------------------------------------
def signing_risk(n, t, l, c, rho):
    unavailable = sum(betabin(x, n, l, rho) for x in range(n - t + 1, n + 1))
    forged = sum(betabin(x, n, c, rho) for x in range(t, n + 1))
    return unavailable, forged

def best_signing(l, c, rho, forge_max=1e-4, nmax=9):
    """Forgery is a catastrophe: first forgery <= forge_max, then minimal unavailability. t>=2 (K-8)."""
    out = []
    for n in range(2, nmax + 1):
        ok = [(signing_risk(n, t, l, c, rho), t) for t in range(2, n + 1)]
        ok = [x for x in ok if x[0][1] <= forge_max]
        if ok:
            (u, f), t = min(ok)
            out.append((n, t, f, u))
    return out


SIGN_GRID = [(l, c, r) for l in (.03, .05, .1) for c in (.005, .01, .02, .03) for r in (.01, .02, .05, .1)]
SIGN_LAMS = (0.02, 0.05, 0.1, 0.2, 0.5)

def signing_robust_choice(nmax=31):
    """Robust choice of the signing scheme (B-1). Loss in scenario s = forgery/1e-4 + unavailability/1e-3
    (normalized to the targets) + lam*n (weight of the number of people; lam is unknown and also enumerated).
    The (n, t), t > n/2, chosen minimizes the largest ratio to the scenario optimum over scenarios and lam.
    Without a weight on the number of people more holders are always better, but with diminishing returns: the common cause sets a limit."""
    cands = [(n, t) for n in range(3, nmax + 1) for t in range(n // 2 + 1, n + 1)]
    L = {}
    for n, t in cands:
        for sc in SIGN_GRID:
            u, f = signing_risk(n, t, *sc); L[(n, t, sc)] = f / 1e-4 + u / 1e-3
    opt = {(sc, lam): min(L[(n, t, sc)] + lam * n for n, t in cands) for sc in SIGN_GRID for lam in SIGN_LAMS}
    ranked = sorted((max((L[(n, t, sc)] + lam * n) / opt[(sc, lam)] for sc in SIGN_GRID for lam in SIGN_LAMS), n, t) for n, t in cands)
    return ranked

# ---------------------------------------------------------------------------
# 3. DISTRIBUTION CHANNELS (B-3)
# ---------------------------------------------------------------------------
def all_channels_fail(m, f, rho):
    return f ** m if rho <= 0 else betabin(m, m, f, rho)


# ---------------------------------------------------------------------------
# 4. TREASURY (Section 16, M-4)
# Sources provide income; each leaves within a year with probability l (common cause rho).
# Worst case of concentration: all sources at the share limit s, ceil(1/s) of them.
# The risk is that departed sources leave income below mandatory expenses (share e of average income).
# Conclusion of the model: with a strong common cause of departure no share limit helps — only a small
# share of mandatory expenses and the reserve protect.
# ---------------------------------------------------------------------------
def treasury_risk(s, e, l, rho):
    n = math.ceil(1 / s)
    return sum(betabin(x, n, l, rho) for x in range(n + 1) if x * s > 1 - e + 1e-12)

def treasury_cap(e, l, rho, eps=0.01):
    """The largest limit s at which risk <= eps for all limits not above s (robust to non-monotonicity)."""
    best = None
    for c in range(1, 101):
        sv = c / 100
        if sv > 1 - e or treasury_risk(sv, e, l, rho) > eps:
            break
        best = sv
    return best


# ---------------------------------------------------------------------------
# 5. CHANNEL KEEPERS (B-3, B-8)
# C channels; each has a team of n keepers with t-of-n access; teams do not overlap,
# they are selected by lot without replacement from N admitted, among whom M = ceil(b*N) are dishonest.
# A channel fails if: (1) its infrastructure is unavailable (prob. f, common cause rho_c between channels);
# (2) captured: dishonest members of the team >= t; (3) blocked: available honest members < t
#    (an honest member is unavailable during a year with prob. l, common cause rho within the team).
# Distribution failure — all C channels fail at once (authenticity of releases is protected by the B-1 signature).
# ---------------------------------------------------------------------------


def hyper(a, N, M, n):
    if a < 0 or a > n or a > M or n - a > N - M: return 0.0
    return math.exp(lcomb(M, a) + lcomb(N - M, n - a) - lcomb(N, n))

def fail_given_a(a, n, t, l, rho):
    if a >= t: return 1.0                                   # capture
    h = n - a
    return sum(betabin(x, h, l, rho) for x in range(h + 1) if h - x < t)   # blocking

def all_people_fail(k, N, M, n, t, l, rho):
    """Probability that all k (of C) channels fail because of people; teams are drawn sequentially."""
    memo = {}
    def rec(i, Nr, Mr):
        if i == k: return 1.0
        key = (i, Nr, Mr)
        if key in memo: return memo[key]
        s = 0.0
        for a in range(0, min(n, Mr) + 1):
            p = hyper(a, Nr, Mr, n)
            if p: s += p * fail_given_a(a, n, t, l, rho) * rec(i + 1, Nr - n, Mr - a)
        memo[key] = s; return s
    return rec(0, N, M)

def p_outage(N, b, C, n, t, l=0.05, rho=0.05, f=0.10, rho_c=0.1):
    if C * n > N: return None
    M = min(N, math.ceil(b * N))
    if f <= 0: return all_people_fail(C, N, M, n, t, l, rho)
    return sum(betabin(j, C, f, rho_c) * all_people_fail(C - j, N, M, n, t, l, rho) for j in range(C + 1))



# ---------------------------------------------------------------------------
# 6. PATENT DETERRENCE (L-9)
# A lawsuit lasts until settlement tau ~ Exp(mu) months; while the license is suspended, the claimant loses v per month.
# Automatic termination: expected loss v*mu. Through the procedure: the measure takes effect after period D
# and only if the violation is proven (prob. P): P*v*E[(tau-D)+] = P*v*mu*exp(-D/mu).
# Relative deterrent strength = P*exp(-D/mu). There is deterrence if the expected loss >= the gain from the suit.
# ---------------------------------------------------------------------------
def patent_deterrence(P, D, mu):
    return P * math.exp(-D / mu)

if __name__ == "__main__":
    print("=== Peer decisions ===")
    for p in (0.6, 0.7, 0.8):
        lo, hi, bmax = theorem_window(0.10, p)
        print(f"p={p}: the block is withstood at b < {bmax:.3f}; at b=0.10 the threshold window is {lo:.2f}..{hi:.2f}")
    print("Effective block share at honest turnout t (b=0.10):", ", ".join(f"t={t}: {0.10/(0.10+0.90*t):.2f}" for t in (1.0, 0.5, 0.3)))
    print("Rule R-3 (tau=0.5, phi=0.20), V=200, p=0.7, rho=0.05: P(adopt harmful) / P(block useful)")
    for t in (0.6, 0.3):
        for b in (0.05, 0.10, 0.15):
            h, s = decision_errors(200, b, t, 0.7, 0.05)
            h0, s0 = decision_errors(200, b, t, 0.7, 0.05, phi=0.0)
            print(f"  turnout {t}, block {b}: with the support threshold {h:.3f}/{s:.3f}; without it {h0:.3f}/{s0:.3f}")
    print("Fake pseudonyms (R-6, R-7): the largest admissible share s with block b")
    for p in (0.6, 0.7, 0.8):
        print(f"  p={p}: " + ", ".join(f"b={b}: s<{sybil_max_share(b, p):.3f}" for b in (0.0, 0.05, 0.10)))
    print("  V=200 real people, p=0.7, rho=0.05, turnout 0.6, block 0.05: P(adopt harmful) / P(block useful)")
    for sv in (0.0, 0.05, 0.10, 0.15, 0.20):
        h, z = decision_errors_sybil(200, 0.05, sv, 0.6, 0.7, 0.05)
        print(f"    share of fakes {sv:.2f} (b'={sybil_effective_block(0.05, sv):.3f}): {h:.3f}/{z:.3f}")
    print("R-7: reconfirmation sample size for a 95% upper bound (0 fakes found, n >= ln(0.05)/ln(1-s))")
    for sv in (0.10, 0.05, 0.02):
        print(f"  bound {sv:.0%}: n >= {math.ceil(math.log(0.05) / math.log(1 - sv))}")
    print("Admission to vote (R-6, R-7): exclusion of steady honest participants under the rule \"m months of W\"")
    for W, m in ((6, 3), (12, 3), (24, 1), (24, 4), (24, 6)):
        print(f"  {m} of {W}: exclusion {honest_exclusion(W, m):.3f}")
    print("  the best rule with a share of fakes <= 5% (delta=0.05):")
    for beta, f, best in admission_levels():
        if best:
            print(f"    adversary {beta:.2f}, voucher deception {f}: W={best[1]} m={best[2]} k={best[3]}, exclusion {best[0][0]:.3f}, fakes {best[4]:.3f}")
        else:
            print(f"    adversary {beta:.2f}, voucher deception {f}: unreachable — a stronger method is needed (R-7)")
    print("\n=== Release signing (target: forgery <= 1e-4 per year) ===")
    for l, c, rho, note in [(0.05, 0.02, 0.05, "software keys, weak diversity"),
                            (0.05, 0.01, 0.02, "hardware keys, different jurisdictions")]:
        print(f" {note} (l={l}, c={c}, rho={rho}):")
        for n, t, f, u in best_signing(l, c, rho):
            print(f"   {t} of {n}: forgery {f:.1e}, unavailability {u:.1e}")
    u, f = signing_risk(1, 1, 0.05, 0.02, 0.0); print(f" for comparison, one key: forgery {f:.1e}, unavailability {u:.1e}")
    ranked = signing_robust_choice()
    print(" robust choice over the scenario grid and the weight of the number of people (worst ratio to the optimum):")
    for v, n, t in ranked[:4]:
        print(f"   {t} of {n}: {v:.2f}")
    worst = {(n, t): v for v, n, t in ranked}
    print(f"   for comparison 4 of 7: {worst[(7, 4)]:.2f}; 7 of 13: {worst[(13, 7)]:.2f}")
    print(" adopted scheme: 9 of 17 (B-1): the difference from the best option is under 2% — within the model's precision;")
    print("   with practical equality the smaller number of people (K-8) and an odd n are chosen")
    u, f = signing_risk(17, 9, 0.05, 0.01, 0.02); print(f" 9 of 17 in the base scenario (hardware, rho=0.02): forgery {f:.1e}, unavailability {u:.1e}")
    print("\n=== Distribution channels (each unavailable within a year with probability 10%) ===")
    for rho in (0.0, 0.1, 0.3):
        print(f" common cause rho={rho}: " + ", ".join(f"{m} ch.: {all_channels_fail(m, 0.10, rho):.1e}" for m in range(1, 6)))
    print("\n=== Treasury: risk within a year that income falls below mandatory expenses (30%), with a share limit of 10% (M-4) ===")
    print("  " + "; ".join(f"departure {l}, common cause {rho}: {treasury_risk(0.10, 0.30, l, rho):.4f}" for l, rho in ((0.1, 0.05), (0.2, 0.05), (0.2, 0.1), (0.3, 0.2))))
    print("  note: the worst case \"all sources at the limit\" gives a non-monotonic dependence on the limit because the number of sources is rounded;")
    print("  so the limit is chosen over a grid of scenarios, not from a single value")
    print("=== Treasury (risk within a year <= 1%) — the largest admissible share limit ===")
    for e in (0.3, 0.5):
        print(f" mandatory {e:.0%} of income: " + "; ".join(
            f"departure {l}, common cause {rho}: share limit {treasury_cap(e, l, rho) or 'unreachable'}"
            for l, rho in ((0.1, 0.05), (0.2, 0.05), (0.3, 0.2))))
    print("\n=== Channel keepers (N=50, dishonest 10%; failure of all channels within a year) ===")
    for C, n, t, name in [(1, 1, 1, "a single keeper in total"), (4, 1, 1, "4 channels with one keeper each"),
                          (6, 4, 2, "6 channels, teams of 2 of 4")]:
        print(f"  {name}: people only {p_outage(50, 0.10, C, n, t, f=0.0):.1e}; with infrastructure failures {p_outage(50, 0.10, C, n, t):.1e}")
    print("  infrastructure only (each channel 10%/year): " + "; ".join(
        f"common cause {rc}: " + ", ".join(f"{C} ch. {betabin(C, C, 0.10, rc):.1e}" for C in (4, 6, 8)) for rc in (0.1, 0.3)))
    print("\n=== Patent deterrence: strength of the procedure relative to automatic termination (D=3 months) ===")
    for P, lab in ((0.97, "full review"), (0.66, "N=15"), (0.14, "N=10")):
        print(f"  probability of proof {P} ({lab}): " + ", ".join(f"suit ~{mu} months: {patent_deterrence(P, 3, mu):.2f}" for mu in (6, 12, 24)))
    print("\n=== Political restrictions (J-11, B-3): share of countries for which all official channels are closed ===")
    for sv, rho, lab in ((0.1, 0.2, "rare, weakly coordinated"), (0.2, 0.5, "bloc-based"), (0.3, 0.7, "hard blocs")):
        print(f"  {lab} (s={sv}, common cause {rho}): " + ", ".join(f"{C} ch. {betabin(C, C, sv, rho):.1e}" for C in (4, 6, 8)))
    print("  conclusion: with coordinated restrictions the number of channels barely helps — channels outside one alliance and free mirrors are needed (B-9)")
