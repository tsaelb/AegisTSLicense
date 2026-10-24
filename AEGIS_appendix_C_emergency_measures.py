#!/usr/bin/env python3
"""
AEGIS — Appendix to the section "Emergency measures" (E).
Part 1: check of the rules by enumerating all sequences of actions over a horizon of HORIZON days.
Part 2: machine proof of an inductive invariant for ANY length of sequence (Z3, if installed).
Status: working material; prepared with the help of AI according to the instructions of the project owner;
requires independent review. English version of «AEGIS_приложение_модель_чрезвычайных_мер.py»; it computes the
same numbers.
RUN: python3 AEGIS_appendix_C_emergency_measures.py [--naive]   (--naive adds the naive scheme; needs ~2 GB of memory)
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
        out.append(("day", (day + 1, cls if nl > 0 else 0, max(nl, 0), ren if nl > 0 else 0,
                            min(counted + 1, CAP + 1), min(actual + 1, CAP + 1), quorum, imminent, kchg)))
    else:
        out.append(("day", (day + 1, 0, 0, 0, counted, actual, quorum, imminent, kchg)))
    out.append(("quorum±", (day, cls, left, ren, counted, actual, not quorum, imminent, kchg)))
    out.append(("risk±", (day, cls, left, ren, counted, actual, quorum, not imminent, kchg)))
    if cls == 0:
        for c in (1, 2, 3):
            if c == 3 and not quorum and not imminent:
                continue
            if design == "fixed" and counted + T[c] > CAP:
                continue
            if design == "flawed" and counted >= CAP:
                continue
            out.append((f"declare cl.{c}", (day, c, T[c], 0, counted, actual, quorum, imminent, kchg)))
            if design == "naive":
                out.append((f"re-declare as new cl.{c}", (day, c, T[c], 0, 0, actual, quorum, imminent, kchg)))
    else:
        if ren < MAXREN and (design == "naive" or counted + left + T[cls] <= CAP):
            out.append(("extend", (day, cls, left + T[cls], ren + 1, counted, actual, quorum, imminent, kchg)))
        out.append(("cancel", (day, 0, 0, 0, counted, actual, quorum, imminent, kchg)))
    # a full independent review opens a new window (the measure must be justified anew)
    out.append(("full review", (day, cls, left, ren, 0, 0, quorum, imminent, kchg)))
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
            if a.endswith("cl.3") and not s[6] and not s[7] and n not in parent:
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
        if a in ("quorum±", "risk±"): continue
        if out and out[-1][0] == a: out[-1][1] += 1
        else: out.append([a, 1])
    return " → ".join(f"{a}×{k}" if k > 1 else a for a, k in out)

designs = (["naive"] if "--naive" in sys.argv else []) + ["flawed", "fixed"]
for design in designs:
    parent, bad = run(design)
    print(f"Scheme \"{design}\": states {len(parent)}; violated properties: {sorted(bad) or 'none'}")
    for prop, s in sorted(bad.items()):
        print(f"  {prop}, counterexample: {path(parent, s)}")


# ---------------- Part 2. Inductive proof (scheme "fixed") ----------------
# Invariant I: 0 <= counted, 0 <= left, counted + left <= CAP, actual == counted.
# We prove: for any integer values and any admissible transition, I => I'.
try:
    import z3
except ImportError:
    print("\nZ3 is not installed (pip install z3-solver) — the inductive proof is skipped"); raise SystemExit
counted, left, actual, Tc, cap = z3.Ints("counted left actual Tc CAP")
c2, l2, a2 = z3.Ints("counted2 left2 actual2")
I = lambda c, l, a: z3.And(c >= 0, l >= 0, c + l <= cap, a == c)
params = z3.And(cap >= 1, Tc >= 1, Tc <= cap)
transitions = {
 "day under a measure": z3.And(left >= 1, c2 == counted + 1, l2 == left - 1, a2 == actual + 1),
 "day without a measure": z3.And(left == 0, c2 == counted, l2 == 0, a2 == actual),
 "declare a measure": z3.And(left == 0, counted + Tc <= cap, c2 == counted, l2 == Tc, a2 == actual),
 "extend": z3.And(left >= 1, counted + left + Tc <= cap, c2 == counted, l2 == left + Tc, a2 == actual),
 "cancel": z3.And(c2 == counted, l2 == 0, a2 == actual),
 "full review": z3.And(c2 == 0, l2 == left, a2 == 0, left <= cap),
}
print("\nInductive proof of invariant I for any length of sequence:")
s = z3.Solver(); s.add(cap >= 1, z3.Not(I(0, 0, 0)))
print("  base (initial state):", "proven" if s.check() == z3.unsat else "NOT proven")
allok = True
for name, tr in transitions.items():
    s = z3.Solver(); s.add(params, I(counted, left, actual), tr, z3.Not(I(c2, l2, a2)))
    r = s.check(); allok &= r == z3.unsat
    print(f"  step \"{name}\":", "preserves the invariant" if r == z3.unsat else f"VIOLATES, counterexample {s.model()}")
print("  conclusion:", "I holds for all reachable states; hence actual <= CAP always (property P2)" if allok else "no proof obtained")
# Control: the "flawed" version of the declaration rule does not preserve the invariant
s = z3.Solver(); s.add(params, I(counted, left, actual), left == 0, counted < cap, c2 == counted, l2 == Tc, a2 == actual, z3.Not(I(c2, l2, a2)))
print("  control: the rule \"declare while the limit is not exhausted\" —", "refuted, counterexample " + str(s.model()) if s.check() == z3.sat else "not refuted")
