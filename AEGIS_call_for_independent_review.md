# AEGIS — call for independent review

*Working material. Published together with the draft License (F-2). Russian version — `AEGIS_призыв_к_независимой_проверке.md`. The review procedure is set by B-6 and Appendix G, computation 11.*

## What is reviewed and why

The draft AEGIS License does not take effect until, for each area below, a round of **8 new independent reviewers** finds no new material error. Rounds are repeated: what is found is fixed, and the next round is carried out by other people.

Such a round guarantees only one thing: an error noticed by at least one reviewer in three would have survived it with a probability of no more than 4%. Hard-to-notice errors may remain. The Project does not claim that there are no errors (K-10).

| Area | Who is needed | Main questions |
|---|---|---|
| Russian text | native speakers of Russian | unambiguity, grammar, no double readings, understandable without a lawyer |
| English text | native speakers of English | the same for English; natural legal style |
| Equivalence of the languages | bilingual readers | do RU and EN say the same thing in every provision (K-0.11); especially the terms below |
| Mathematics of the models | statisticians, decision theorists | assumptions of Appendices A, B, E, G; scenario grids; selection criteria; correctness of formulas |
| Cryptography and the Trust System | cryptographers, security specialists | B-1, B-4, B-7, B-11, B-12, P-13; Appendices D, F, H; post-quantum signatures; hash renewal |
| Formal models | formal verification specialists | translation of the Core into Z3 formulas; the inductive proof of Appendix C; completeness of the control experiments |
| Logic of the Core | any careful reader | contradictions, loopholes, circumvention of protective purposes (K-0.5), unfairness to the restricted person |

## Who may review

- Anyone — through the open call. The author of the text does not choose reviewers.
- Independence follows definition 21. A reviewer must have no ties of categories 1–4 under U-5 to the author of the initial text: employment or payment, an interested Power Structure, a personal tie. A tie is declared by category, without names of organizations or people; instead of disclosing, one may recuse.
- Acting under a pseudonym is allowed.
- Payment from the author is not accepted.
- One person may review several areas. In the next round of the same area that person no longer counts as "new".

## How to run everything yourself

You need Python 3, `numpy`, `scipy`, `z3-solver`, `cryptography` (a version with ML-DSA).

```
python3 -I tools/check_all.py
```

The script compares both texts: the number and order of provisions, definitions, references and numbers. It then runs all appendices in both languages, checks their key conclusions and that the English and Russian versions give the same numbers. Then come the Z3 check of the Core with control experiments and the mutation testing of the tests of Appendix H. Each appendix can also be run separately; its assumptions are listed at the beginning of each file and in the table of assumptions.

## Terms where the languages are most likely to diverge

| RU | EN | What to look at |
|---|---|---|
| Распорядитель | Steward | not confused with channel keepers (хранители); R-9 |
| Основание | Grounds | everyday sense versus definition 18 |
| Существенный | Material | the same threshold in both languages |
| Независимый | Independent | application to channels and sources, not only to people |
| Добросовестный / Добросовестно получивший | Good Faith / Good-Faith Recipient | fault and knowledge — the same? |
| Произведение / Произведение на основе | Work / Derived Work | scope: programs created with AEGIS tools (K-0.8) |
| Передача / Предоставление через сеть | Transfer / Network Provision | within an organization; through other programs |
| Скрытый / скрыто | Hidden / covertly | "not notified in advance" and "presented as something else" |
| Властная структура | Power Structure | whether military and political forces are included in the same way |
| Сведения о людях | Information about People | public, anonymized, aggregated |
| травить или выслеживать | harass or track | K-24: has the prohibition narrowed or widened? |
| произвольно — без основания и без независимой проверки | arbitrarily — without Grounds and without independent review | K-24 |
| Защитная мера | protective measure | that it is not punishment (K-0.12) |

Capitalization does not change meaning: a defined term means the same in any case and grammatical form.

## How to report a finding

1. In the open review log: the provision, a quotation, what the error is, a proposed correction. Secrets and Information about People are not published.
2. State the area and an assessment — material or not material (definition 19).
3. Every finding receives a public response: fixed, rejected with reasons, or left open. A rejection may be challenged.
4. A reviewer is not obliged to find anything. A record "reviewed area X, no new material errors" is a full result and counts towards the round.

## What has already been checked automatically

Repeating this is not needed; checking that it is correct is.

- The Core has no contradictions within its translation into formulas (Z3; two control experiments find the planted conflicts).
- The numbers in the text match the outputs of the models; RU and EN match in numbers and structure.
- The properties of emergency measures are proven by induction for any duration (Appendix C).
- The order of choice in K-0.14 always gives an answer; checked by exhaustive enumeration of 88,641 sets.
- The Trust System has a reference implementation (Appendix H): 27 attack tests; all 13 deliberately weakened versions of the rules are detected by the tests.

Not checked, because it does not exist yet: the behaviour of the compiler and runtime of the AEGIS language (T-1–T-10, C-1–C-7).
