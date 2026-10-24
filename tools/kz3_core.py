"""Z3: непротиворечивость ядра AEGIS (текущая редакция) — для каждой допустимой ситуации существует набор действий,
удовлетворяющий всем положениям. Проверка квантором: ∃обстоятельства ∀действия ¬(ядро). Найденные противоречия
перечисляются с ядром противоречия (минимальным набором положений). Перевод положений в формулы сделан составителем
и сам требует проверки (K-10).
EN: Z3 consistency of the AEGIS Core — for every admissible situation there is a set of actions satisfying all provisions
(quantified check ∃circumstances ∀actions ¬Core), with sensitivity controls. The translation of provisions into formulas
was made by the drafter and itself requires review (K-10). Rule names are in Russian."""
import sys, z3

F = ["f_vuln_known", "f_disclosure_risky", "f_ongoing_proven", "f_decision_affects", "f_evidence_secret",
     "f_secret_basis", "f_closed_lib", "f_author_wants_anon", "f_lang_conflict",
     "f_ai_generated", "f_requester_consents", "f_trained_on_aegis", "f_model_shared",
     "f_program_in_aegis_lang", "f_uses_aegis_work", "f_independent_impl", "f_accepted_license",
     "f_actor_accepted", "f_law_compels_block", "f_violation_stopped", "f_mandatory_unverified",
     "f_audit_requested", "f_repetition", "f_risk_higher", "f_na_justified",
     "f_owner_permission", "f_rule_authority", "f_self_regarding",
     "f_detention_grounds", "f_detention_reviewed", "f_authorized_recipient"]
A = ["a_transfer", "a_network", "a_give_source", "a_reveal_secret", "a_inform_affected", "a_delay_disclosure",
     "a_suspend", "a_grounds_full", "a_safe_summary", "a_contest", "a_hidden_telemetry", "a_accept_cond_funding",
     "a_remove_attribution", "a_edit_K", "a_relicense_derived", "a_protective_reading", "a_honor_identity_request",
     "a_mark", "a_mark_names_requester", "a_remove_mark", "a_open_model", "a_reveal_people_data",
     "a_license_binds_program", "a_use_designation", "a_oblige_actor_mark", "a_oblige_actor_open_model", "a_person_blocks", "a_project_rule_block", "a_deviation_recorded",
     "a_restore", "a_require_admission", "a_claim_full_conformity", "a_declare_violation",
     "a_audit_scheduled", "a_refusal_justified", "a_stricter_measure", "a_mark_na", "a_protocol_changes_K",
     "a_access_others", "a_self_authorize", "a_restrict_self_choice", "a_offer_help", "a_manipulate",
     "a_detain_with_work", "a_track_person", "a_grant_rights"]
v = {n: z3.Bool(n) for n in F + A}
I, And, Or, Not = z3.Implies, z3.And, z3.Or, z3.Not

FACT_LOGIC = [
    I(v["f_independent_impl"], Not(v["f_uses_aegis_work"])),      # С-1: независимая реализация не использует произведений
    I(v["f_uses_aegis_work"], v["f_accepted_license"]),             # K-0.8: использование = принятие
    I(v["f_actor_accepted"], v["f_accepted_license"]),
]

def core(k08_variant):
    r = {
     "K-19 открытость": I(Or(v["a_transfer"], v["a_network"]), v["a_give_source"]),
     "Опр.6 исходный текст": I(And(v["a_give_source"], v["f_closed_lib"]), z3.BoolVal(False)),
     "K-5 секреты": I(v["a_reveal_secret"], v["f_secret_basis"]),
     "K-21 известные провалы": I(v["f_vuln_known"], Or(v["a_inform_affected"], And(v["f_disclosure_risky"], v["a_delay_disclosure"]))),
     "K-21 отсрочка только при риске": I(v["a_delay_disclosure"], v["f_disclosure_risky"]),
     "K-2 оспаривание": I(v["f_decision_affects"], And(Or(v["a_grounds_full"], v["a_safe_summary"]), v["a_contest"])),
     "Опр.15 безопасные пределы": I(And(v["a_grounds_full"], v["f_evidence_secret"]), v["a_reveal_secret"]),
     "K-15 приостановление": I(v["a_suspend"], And(v["f_ongoing_proven"], Or(v["a_grounds_full"], v["a_safe_summary"]), v["a_contest"])),
     "K-7 наблюдение": Not(v["a_hidden_telemetry"]),
     "K-23 независимость": Not(v["a_accept_cond_funding"]),
     "K-18 авторство": I(v["a_remove_attribution"], v["f_author_wants_anon"]),
     "K-16 автономия": I(v["f_author_wants_anon"], v["a_honor_identity_request"]),
     "Смысл просьбы об анонимности": I(v["a_honor_identity_request"], v["a_remove_attribution"]),
     "K-0.2 неизменность": Not(v["a_edit_K"]),
     "K-22 ядро следует": Not(v["a_relicense_derived"]),
     "K-0.11 два языка": I(v["f_lang_conflict"], v["a_protective_reading"]),
     "K-25 отметка": I(And(v["f_ai_generated"], v["f_uses_aegis_work"]), And(v["a_mark"], Not(v["a_remove_mark"]))),
     "K-25 без сведений о запросившем": I(v["a_mark_names_requester"], v["f_requester_consents"]),
     "K-26 открытость модели": I(And(v["f_trained_on_aegis"], v["f_model_shared"]), v["a_open_model"]),
     "K-26 без сведений о людях": Not(v["a_reveal_people_data"]),
     "K-0.8 лицензия не властна над не принимавшими": I(v["a_license_binds_program"], v["f_accepted_license"]),
     "K-0.8 нет обязанностей у не принимавшего": And(I(v["a_oblige_actor_mark"], v["f_actor_accepted"]), I(v["a_oblige_actor_open_model"], v["f_actor_accepted"])),
     "K-25 обязывает лицензиата": I(And(v["f_ai_generated"], v["f_actor_accepted"]), v["a_oblige_actor_mark"]),
     "K-19 права каждому соблюдающему (проект не вводит ограничений по стране)": Not(v["a_project_rule_block"]),
     "Ю-11 принуждённый участник подчиняется закону": I(v["f_law_compels_block"], v["a_person_blocks"]),
     "K-0.9/Ю-11 личное отступление фиксируется и не становится правилом": I(v["a_person_blocks"], And(v["f_law_compels_block"], v["a_deviation_recorded"], Not(v["a_project_rule_block"]))),
     "П-10 восстановление после прекращения нарушения": I(And(v["f_violation_stopped"], Not(v["f_ongoing_proven"])), v["a_restore"]),
     "K-0.12/П-10 восстановление без признания и извинения": Not(v["a_require_admission"]),
     "С-7 непроверенное обязательное исключает полное соответствие": I(v["f_mandatory_unverified"], Not(v["a_claim_full_conformity"])),
     "K-0.7/С-7 нарушение — только доказанное": I(v["a_declare_violation"], v["f_ongoing_proven"]),
     "П-19 запрос аудита: аудит или обоснованный отказ": I(v["f_audit_requested"], Or(v["a_audit_scheduled"], v["a_refusal_justified"])),
     "П-18 повторяемость не ужесточает меру без роста риска": I(v["a_stricter_measure"], v["f_risk_higher"]),
     "С-7 «не применимо» только с обоснованием": I(v["a_mark_na"], v["f_na_justified"]),
     "Ф-1 протоколы не меняют ядро": Not(v["a_protocol_changes_K"]),
     "K-14/опр.26 доступ к чужому — только с разрешением или полномочием по правилам": I(v["a_access_others"], Or(v["f_owner_permission"], v["f_rule_authority"])),
     "опр.26 самоназначение не даёт полномочия": I(And(v["a_self_authorize"], Not(v["f_owner_permission"]), Not(v["f_rule_authority"])), Not(v["a_access_others"])),
     "K-16 решения о себе не ограничиваются": I(v["f_self_regarding"], Not(v["a_restrict_self_choice"])),
     "K-0.12 помощь доказанному нарушителю без манипуляции": And(I(v["f_ongoing_proven"], v["a_offer_help"]), Not(v["a_manipulate"])),
     "K-24 лишение свободы — только с основанием и независимой проверкой": I(v["a_detain_with_work"], And(v["f_detention_grounds"], v["f_detention_reviewed"])),
     "K-24 травля и выслеживание запрещены": Not(v["a_track_person"]),
     "K-19/Л-1 права — только получателю с разрешения": I(v["a_grant_rights"], v["f_authorized_recipient"]),
     "K-26 обязывает обучившего на полученном по лицензии": I(And(v["f_trained_on_aegis"], v["f_actor_accepted"]), v["a_oblige_actor_open_model"]),
    }
    if k08_variant == "текущий":
        r["K-0.8 программы на языке — под лицензией"] = I(v["f_program_in_aegis_lang"], v["a_license_binds_program"])
    elif k08_variant == "предлагаемый":
        r["K-0.8 программы, созданные с произведениями AEGIS, — под лицензией"] = I(And(v["f_program_in_aegis_lang"], v["f_uses_aegis_work"]), v["a_license_binds_program"])
        r["K-0.8 без произведений AEGIS — без обозначения"] = I(And(v["f_program_in_aegis_lang"], Not(v["f_uses_aegis_work"])), Not(v["a_use_designation"]))
    return r

def conflicts(variant, limit=50):
    rules = core(variant)
    s = z3.Solver()
    acts = [v[a] for a in A]
    s.add(*FACT_LOGIC)
    s.add(z3.ForAll(acts, Not(And(*rules.values()))))
    found = []
    while len(found) < limit and s.check() == z3.sat:
        m = s.model()
        facts = [v[f] if z3.is_true(m.eval(v[f], model_completion=True)) else Not(v[f]) for f in F]
        t = z3.Solver(); tags = {}
        for name, c in rules.items():
            b = z3.Bool("T:" + name); tags[str(b)] = name; t.assert_and_track(c, b)
        fb = {}
        for lit in facts:
            b = z3.Bool("F:" + str(lit)); fb[str(b)] = lit; t.assert_and_track(lit, b)
        t.check()
        uc = [str(c) for c in t.unsat_core()]
        names = tuple(sorted(tags[c] for c in uc if c in tags))
        lits = [fb[c] for c in uc if c in fb]
        found.append((names, [str(l) for l in lits]))
        s.add(Not(And(*lits)) if lits else z3.BoolVal(False))
    return found

def designation_conflicts(with_rule=True):
    import itertools
    f = {n: z3.Bool(n) for n in ["d_company", "d_name_aegis", "d_mark", "d_disclaimer"]}
    a = {n: z3.Bool(n) for n in ["d_controls_designation", "d_appears_representative"]}
    rules = {
     "K-23 властная структура не решает судьбу обозначения": I(f["d_company"], Not(a["d_controls_designation"])),
     "право знака: держатель решает об использовании": I(And(f["d_mark"], f["d_company"]), a["d_controls_designation"]),
     "О-2/Д-1 никто не представляет проект": Not(a["d_appears_representative"]),
     "смешение без оговорки": I(And(f["d_company"], f["d_name_aegis"], Not(f["d_disclaimer"])), a["d_appears_representative"]),
    }
    allowed = [I(And(f["d_company"], f["d_name_aegis"]), f["d_disclaimer"]), Not(f["d_mark"])] if with_rule else []
    bad = 0
    for bits in itertools.product([False, True], repeat=4):
        fa = [x if b else Not(x) for x, b in zip(f.values(), bits)]
        s0 = z3.Solver(); s0.add(*allowed, *fa)
        if s0.check() == z3.unsat: continue
        s = z3.Solver(); s.add(*rules.values(), *fa); bad += s.check() == z3.unsat
    return bad

if __name__ == "__main__":
    print(f"Обозначение (Л-10, Л-11): без правила {designation_conflicts(False)} противоречий, с правилом {designation_conflicts(True)}")
    variants = sys.argv[1:] or ["текущий", "предлагаемый"]
    for var in variants:
        c = conflicts(var)
        print(f"Ядро, вариант K-0.8 «{var}»: противоречивых классов ситуаций {len(c)}")
        for names, lits in c:
            print("   конфликт:", " + ".join(names), "| при обстоятельствах:", ", ".join(lits))
    _orig = core
    def _old_k18(var):
        r = _orig(var); r["K-18 авторство"] = Not(v["a_remove_attribution"]); return r
    core = _old_k18
    ctrl = conflicts(variants[-1]); core = _orig
    print("Контроль чувствительности (старая K-18 без исключения должна дать конфликт):", "обнаружен" if ctrl else "НЕ обнаружен")
    _orig2 = core
    def _apology(var):
        r = _orig2(var); r["(контроль) восстановление при условии извинения"] = I(v["a_restore"], v["a_require_admission"]); return r
    core = _apology; ctrl2 = conflicts(variants[-1]); core = _orig2
    print("Контроль чувствительности 2 (восстановление при условии извинения должно дать конфликт):", "обнаружен" if ctrl2 else "НЕ обнаружен")
    print("Невыполнимых комбинаций:", len(conflicts(variants[-1])) if ctrl else "проверка недействительна")
