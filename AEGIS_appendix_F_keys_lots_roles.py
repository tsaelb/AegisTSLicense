#!/usr/bin/env python3
"""
AEGIS — Appendix F. Keys, lots, separation of roles, freshness and case records
(B-4, B-10, B-11, B-12, U-8, P-13).

Status: working material. Prepared with the help of AI according to the instructions of the project owner;
requires independent review. The translation of provisions into formulas was made by the drafter and itself
requires review (K-10). English version of «AEGIS_приложение_ключи_жребий_роли.py»; it computes the same numbers.
RUN: python3 AEGIS_appendix_F_keys_lots_roles.py   (requires the z3-solver package)

1. Uniqueness of continuation (Z3, proof for all subsets): with t-of-n signing and t > n/2, two disjoint
   sets of holders cannot both collect t signatures; with t <= n/2 they can.
2. Recovery of the key set (B-11): if fewer than t holders are available, ordinary rotation (B-2) is impossible
   forever — checked by enumerating states; with rule B-11 the "deadlock" state is unreachable.
3. Lot (B-12): withholding attack in a commit–reveal scheme. Monte Carlo: bias without an external source
   and with an external source that is unknown at the moment of deciding whether to reveal.
4. Separation of roles (U-8): probability that one person ends up in several roles at once
   (key holder, keeper, treasury signatory) if roles are assigned by lot without a ban on combining them.
5. Freshness of status (B-4): rollback attack — compromised channels show an outdated but correctly
   signed status (for example, before revocation of a key or release). Probability of accepting it under the rule
   "match in 2 channels" and "match in a majority of channels" with compromise having a common cause.
6. Case records (P-13): Z3 — a request to delete personal data that is evidence in an unfinished case,
   against the prohibition on destroying evidence: a contradiction without the rule, none with the rule.
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

# 1. Uniqueness of continuation --------------------------------------------------
def two_disjoint_quorums_possible(n, t):
    """Z3: do there exist two disjoint sets of holders, each of size at least t."""
    A = [z3.Bool(f"a{i}") for i in range(n)]; B = [z3.Bool(f"b{i}") for i in range(n)]
    s = z3.Solver()
    s.add(*[z3.Not(z3.And(A[i], B[i])) for i in range(n)])
    s.add(z3.PbGe([(x, 1) for x in A], t), z3.PbGe([(x, 1) for x in B], t))
    return s.check() == z3.sat

# 2. Recovery of the key set -----------------------------------------------------
def deadlock_reachable(n, t, with_recovery, steps=12):
    """The state is the number of available holders k. Loss of a key: k -> k-1. Rotation (B-2): with k >= t
    the set is replenished to n. Recovery (B-11): with k < t a new set is formed under B-11 (lot + vote)."""
    seen = {n}; frontier = {n}
    for _ in range(steps):
        nxt = set()
        for k in frontier:
            if k > 0: nxt.add(k - 1)
            if k >= t: nxt.add(n)
            if k < t and with_recovery: nxt.add(n)
        frontier = nxt - seen; seen |= nxt
    # deadlock — a state from which k >= t is unreachable
    def can_recover(k):
        return k >= t or with_recovery
    return any(not can_recover(k) for k in seen)

# 3. Lot ---------------------------------------------------------------------------
def lottery_bias(members=20, attackers=3, seats=7, trials=20000, beacon=False, seed=1):
    """The adversary's goal is to increase the number of its seats. Without an external source the last revealer
    sees others' reveals and decides for each of its participants "reveal / withhold" (a non-revealer drops out
    of the lot), choosing the best of 2^attackers outcomes. With an external source (the hash of a block at a
    height that comes after the reveal deadline) the outcome is unknown at decision time — the choice gives no
    information."""
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
            # the decision is made before the external value appears: the adversary picks the mask that
            # maximizes the expectation, but the expectation is the same for any mask ~ the share present
            mask = (1 << attackers) - 1
            total += outcome(mask, beacon_val)
        else:
            total += max(outcome(mask, None) for mask in range(1 << attackers))
    return total / trials, honest_expect

# 4. Separation of roles -----------------------------------------------------------
def p_someone_multi_role(N, sizes):
    """Roles are filled by an independent lot from N without a ban on combining. Probability that at least one
    person received two roles or more (via the complement — all roles fell into disjoint sets)."""
    p_disjoint = 1.0; used = 0
    for s in sizes:
        p_disjoint *= math.exp(lcomb(N - used, s) - lcomb(N, s)); used += s
    return 1 - p_disjoint

def p_adversary_two_roles(N, b, sizes):
    """Share of dishonest b; probability that at least one dishonest person received two roles."""
    M = math.ceil(b * N)
    # expected number of dishonest people with >=2 roles (an upper bound on the probability by Markov's inequality)
    ps = [s / N for s in sizes]
    p_two = 1 - math.prod(1 - p for p in ps) - sum(p * math.prod(1 - q for j, q in enumerate(ps) if j != i) for i, p in enumerate(ps))
    return min(1.0, M * p_two)

# 5. Freshness of status -----------------------------------------------------------
def p_accept_forged(C, rule, c, rho):
    """Worst case: compromised channels are coordinated; honest ones show the fresh status."""
    if rule == "2 channels":
        return sum(betabin(x, C, c, rho) for x in range(2, C + 1))      # two agreeing forged channels are enough
    maj = C // 2 + 1
    return sum(betabin(x, C, c, rho) for x in range(maj, C + 1))

# 6. Case records ------------------------------------------------------------------
def records_conflicts(with_rule):
    f = {n: z3.Bool(n) for n in ["f_request_delete", "f_is_evidence", "f_case_open"]}
    a = {n: z3.Bool(n) for n in ["a_delete", "a_seal", "a_keep_public"]}
    I, And, Not = z3.Implies, z3.And, z3.Not
    rules = {
        "K-16/K-6: a request to delete personal data is honoured": I(f["f_request_delete"], Not(a["a_keep_public"])),
        "K-6: evidence of an unfinished case may not be destroyed": I(And(f["f_is_evidence"], f["f_case_open"]), Not(a["a_delete"])),
        "meaning: honouring the request = deleting": I(And(f["f_request_delete"], Not(a["a_keep_public"])), a["a_delete"]) if not with_rule
            else I(And(f["f_request_delete"], Not(a["a_keep_public"])), z3.Or(a["a_delete"], And(a["a_seal"], f["f_is_evidence"], f["f_case_open"]))),
    }
    bad = 0
    for bits in itertools.product([False, True], repeat=3):
        s = z3.Solver(); s.add(*rules.values(), *[x if b_ else Not(x) for x, b_ in zip(f.values(), bits)])
        bad += s.check() == z3.unsat
    return bad

if __name__ == "__main__":
    if z3 is None:
        print("the z3-solver package is required"); sys.exit(1)
    print("=== 1. Uniqueness of continuation (Z3) ===")
    for n, t in ((17, 9), (17, 8), (7, 4), (7, 3)):
        r = two_disjoint_quorums_possible(n, t)
        print(f"  {t} of {n}: two disjoint quorums {'ARE POSSIBLE' if r else 'are impossible (proven)'}")
    print("=== 2. Deadlock of the key set (enumeration of states) ===")
    for rec in (False, True):
        print(f"  {'with' if rec else 'without'} B-11: deadlock {'reachable' if deadlock_reachable(17, 9, rec) else 'unreachable'}")
    print("=== 3. Lot: average number of the adversary's seats (3 of 20 participants, 7 seats; honest expectation 1.05) ===")
    for bc in (False, True):
        m, h = lottery_bias(beacon=bc, trials=4000)
        print(f"  {'with an external source (B-12)' if bc else 'without an external source'}: {m:.2f} (honest {h:.2f}, bias {m / h - 1:+.0%})")
    print("=== 4. Combining roles without a ban (17 holders, 6 teams of 4 keepers, 5 treasury signatories) ===")
    for N in (60, 100, 300):
        print(f"  N={N}: at least one person in several roles {p_someone_multi_role(N, [17, 24, 5]):.2f}; "
              f"a dishonest person (10%) in two roles at most {p_adversary_two_roles(N, 0.10, [17, 24, 5]):.2f}")
    print("=== 5. Freshness: probability of accepting an outdated status in a rollback (6 channels) ===")
    for c, rho in ((0.05, 0.1), (0.10, 0.3)):
        print(f"  compromise {c}, common cause {rho}: rule \"2 channels\" {p_accept_forged(6, '2 channels', c, rho):.1e}; "
              f"\"majority of channels\" {p_accept_forged(6, 'majority', c, rho):.1e}")
    print("=== 6. Case records (Z3) ===")
    print(f"  without rule P-13: contradictory situations {records_conflicts(False)}; with the rule: {records_conflicts(True)}")
