#!/usr/bin/env python3
"""
AEGIS — Appendix E. Courts and the Project's procedure (Section 13, J-6 … J-9).
Status: working material. Prepared with the help of AI according to the instructions of the project owner;
requires independent review. The translation of provisions into formulas was made by the drafter and itself
requires review (K-10). English version of «AEGIS_приложение_суд_и_процедура.py»; it computes the same numbers.
RUN: python3 AEGIS_appendix_E_courts_and_procedure.py   (requires the z3-solver package)
Assumptions of part 2: errors of the court and of Section 7 are independent given the truth; the error rates of
Section 7 come from Appendix A.
"""

import itertools, z3, sys

F = ["f_sec7_done", "f_sec7_found", "f_sec7_stalled", "f_need_court", "f_court_found",
     "f_court_binding", "f_order_contrary_core", "f_harm_people", "f_order_restricts", "f_imminent"]
A = ["a_sue", "a_claim_cessation", "a_claim_punitive", "a_claim_restitution", "a_comply_order",
     "a_disclose_coercion", "a_treat_as_interpretation", "a_restrict", "a_publish_both", "a_rereview", "a_edit_K"]
v = {n: z3.Bool(n) for n in F + A}
I, And, Or, Not = z3.Implies, z3.And, z3.Or, z3.Not

core = {
 "K-15 no punishment": Not(v["a_claim_punitive"]),
 "K-15 restriction only when proven": I(And(v["a_restrict"], Not(v["a_comply_order"])), v["f_sec7_found"]),
 "K-23 power does not interpret the Core": Not(v["a_treat_as_interpretation"]),
 "K-0.9 coercion is disclosed": I(And(v["a_comply_order"], v["f_order_contrary_core"]), v["a_disclose_coercion"]),
 "K-0.2 the Core does not change": Not(v["a_edit_K"]),
}
facts_logic = {
 "Section 7: found only on completion": I(v["f_sec7_found"], v["f_sec7_done"]),
 "stalled means not completed": I(v["f_sec7_stalled"], Not(v["f_sec7_done"])),
}

STRICT = "strict \"procedure first\""
NOCOERCION = "follow Section 7 without the coercion clause"
PROPOSED = "proposed"

def rules(variant):
    r = {
     "J-6 right to a court": I(And(v["f_need_court"], Or(v["f_sec7_done"], v["f_sec7_stalled"], v["f_imminent"])), v["a_sue"]),
     "J-7(a) a claim — only cessation or compensation": I(v["a_sue"], Or(v["a_claim_cessation"], v["a_claim_restitution"])),
     "J-7(a) compensation — only for actual harm to people": I(v["a_claim_restitution"], v["f_harm_people"]),
     "J-8(b) a binding court decision is complied with": I(v["f_court_binding"], v["a_comply_order"]),
     "meaning: the court decision requires restricting rights": I(And(v["a_comply_order"], v["f_order_restricts"]), v["a_restrict"]),
     "J-9(c) divergence: both decisions are published": I(And(v["f_sec7_done"], v["f_court_found"] != v["f_sec7_found"]), v["a_publish_both"]),
    }
    if variant == STRICT:
        r["J-6 right to a court"] = I(v["f_need_court"], v["a_sue"])
        r["J-7(a) a claim only after Section 7"] = I(v["a_sue"], v["f_sec7_done"])
    if variant == NOCOERCION:
        r["J-9(c) the Project follows Section 7"] = I(v["f_sec7_done"], v["a_restrict"] == v["f_sec7_found"])
    if variant == PROPOSED:
        r["J-6 a claim after Section 7, its delay, or under immediate risk"] = I(v["a_sue"], Or(v["f_sec7_done"], v["f_sec7_stalled"], v["f_imminent"]))
        r["J-9(c) follow Section 7 absent coercion"] = I(And(v["f_sec7_done"], Not(v["a_comply_order"])), v["a_restrict"] == v["f_sec7_found"])
    return r

def run(variant):
    bad = {}
    for bits in itertools.product([False, True], repeat=len(F)):
        s = z3.Solver(); tags = {}
        for name, c in {**core, **facts_logic, **rules(variant)}.items():
            t = z3.Bool("T:" + name); tags[str(t)] = name; s.assert_and_track(c, t)
        fa = [v[f] if b else Not(v[f]) for f, b in zip(F, bits)]
        s.add(*fa)
        # exclude circumstances that are impossible in themselves
        s0 = z3.Solver(); s0.add(*facts_logic.values(), *fa)
        if s0.check() == z3.unsat:
            continue
        if s.check() == z3.unsat:
            k = tuple(sorted(tags[str(c)] for c in s.unsat_core()))
            bad[k] = bad.get(k, 0) + 1
    return bad

print("=== 1. Z3: satisfiability of the rules together with the Core (enumeration of 2^10 circumstances) ===")
for var in [STRICT, NOCOERCION, PROPOSED]:
    bad = run(var)
    print(f"Variant [{var}]: contradictory situations {sum(bad.values())}")
    for k, n in bad.items():
        print("   conflict:", " + ".join(k), f"({n})")

# witness: in the proposed variant a court is available and punishment is impossible
s = z3.Solver(); s.add(*core.values(), *facts_logic.values(), *rules(PROPOSED).values())
s.add(v["f_need_court"], v["f_sec7_stalled"]); print("Court available when the procedure is delayed:", s.check())
s2 = z3.Solver(); s2.add(*core.values(), *rules(PROPOSED).values(), v["a_claim_punitive"]); print("Punishment can be claimed:", s2.check())

print("\n=== 2. Errors when the court and Section 7 diverge (Appendix A: n=79, k=51) ===")
FPs, FNs = 9.2e-7, 0.026                 # Section 7 (n=79, k=51): false "proven" / false "not proven"
w = 20                                    # a false restriction of rights is w times worse than a miss (doubt favours the restricted person)
print(f"Loss = {w}·P(false restriction) + P(missed violation); court: false \"violation\" c1, false \"none\" c2")
for c1, c2 in [(0.01, 0.10), (0.05, 0.20), (0.10, 0.30)]:
    pol = {
     "follow the court": (c1, c2),
     "follow Section 7": (FPs, FNs),
     "restrict if either found": (1 - (1 - FPs) * (1 - c1), FNs * c2),
     "restrict only if both found": (FPs * c1, 1 - (1 - FNs) * (1 - c2)),
     "Section 7 + re-review when \"court: none\"": (FPs * (1 - c1) * FPs + FPs * c1, FNs + (1 - FNs) * (1 - c2) * FNs),
    }
    print(f" court c1={c1}, c2={c2}:")
    for name, (fp, fn) in sorted(pol.items(), key=lambda x: w * x[1][0] + x[1][1]):
        print(f"   {name:45s} false restriction {fp:.1e}, miss {fn:.3f}, loss {w*fp+fn:.4f}")

thr = ((FNs + (1 - FNs) * 0.9 * FNs) - FNs) / (FPs - FPs * FPs)
print(f"Threshold (court c2=0.10): re-review is better only if a false restriction is worse than a miss by more than {thr:.0f} times")
