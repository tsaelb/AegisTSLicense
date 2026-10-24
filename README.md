# AEGIS — проект лицензии / draft license

**RU.** Это проект лицензии AEGIS для открытого обсуждения и независимой проверки. До выпуска по положению В-6 он как лицензия не действует (О-2). Русский и английский тексты равно авторитетны (K-0.11). Текст и приложения подготовлены с помощью ИИ по решениям и под контролем владельца проекта.

**EN.** This is the draft AEGIS License for open discussion and independent review. Until release under provision B-6 it does not operate as a license (F-2). The Russian and English texts are equally authoritative (K-0.11). The text and appendices were prepared with the help of AI, according to the decisions and under the control of the project owner.

## Состав / Contents

Каждый документ и каждое приложение есть на двух языках. / Every document and every appendix exists in both languages.

| Русский | English | Что это / What it is |
|---|---|---|
| `AEGIS_License_RU.md` | `AEGIS_License_EN.md` | текст лицензии / the License text |
| `AEGIS_призыв_к_независимой_проверке.md` | `AEGIS_call_for_independent_review.md` | призыв к независимой проверке / call for independent review |
| `AEGIS_CORE_прослеживаемость.csv` | `AEGIS_CORE_traceability.csv` | прослеживаемость требований / traceability |
| `AEGIS_стресс_тесты_повторно.csv` | `AEGIS_stress_tests.csv` | стресс-тесты / stress tests |
| `AEGIS_допущения_моделей.csv` | `AEGIS_model_assumptions.csv` | допущения моделей / model assumptions |
| `AEGIS_приложение_модель_проверки.py` | `AEGIS_appendix_A_review_model.py` | Приложение А / Appendix A |
| `AEGIS_приложение_модели_управления.py` | `AEGIS_appendix_B_governance_models.py` | Приложение Б / Appendix B |
| `AEGIS_приложение_модель_чрезвычайных_мер.py` | `AEGIS_appendix_C_emergency_measures.py` | Приложение В / Appendix C |
| `AEGIS_приложение_хеш_ядра.py` | `AEGIS_appendix_D_core_hash.py` | Приложение Г / Appendix D |
| `AEGIS_приложение_суд_и_процедура.py` | `AEGIS_appendix_E_courts_and_procedure.py` | Приложение Д / Appendix E |
| `AEGIS_приложение_ключи_жребий_роли.py` | `AEGIS_appendix_F_keys_lots_roles.py` | Приложение Е / Appendix F |
| `AEGIS_приложение_пороги_и_параметры.py` | `AEGIS_appendix_G_thresholds_and_parameters.py` | Приложение Ж / Appendix G |
| `AEGIS_приложение_эталон_проверки.py` | `AEGIS_appendix_H_reference_verification.py` | Приложение З / Appendix H |

Обе версии каждого приложения вычисляют одни и те же числа; `tools/check_all.py` проверяет это автоматически. / Both versions of each appendix compute the same numbers; `tools/check_all.py` checks this automatically.

| Файл / File | Что это / What it is |
|---|---|
| `README.md`, `CORE-ID.txt`, `LICENSES/LicenseRef-AEGIS-Draft.txt` | двуязычные / bilingual |
| `SHA512SUMS`, `SHA3-512SUMS` | манифест всех файлов / manifest of all files |
| `*.asc`, `*.mldsa65.sig`, `*.ots`, `keys/` | подписи, отметки времени, открытые ключи / signatures, timestamps, public keys |
| `editions/<тег>/` | манифесты, подписи и отметки прежних редакций — остаются проверяемыми / manifests, signatures and timestamps of earlier editions — remain verifiable |
| `tools/` | проверка пакета, манифест, постквантовая подпись (описание на двух языках) / package check, manifest, post-quantum signature (bilingual descriptions) |

## Проверка / Verification

```
sha512sum -c SHA512SUMS                                   # хеши файлов / file hashes
python3 -I tools/manifest.py check                        # SHA-512 + SHA3-512 и идентификатор ядра
gpg --import keys/aegis-public-key.asc                    # ключ 915E 38B7 2359 8D21 CCC3 BA20 8286 646F ED17 D439
gpg --verify SHA512SUMS.asc SHA512SUMS
gpg --verify SHA3-512SUMS.asc SHA3-512SUMS
python3 tools/pq_sign.py verify keys/aegis_mldsa65.pub SHA512SUMS SHA3-512SUMS
ots verify SHA512SUMS.ots                                 # отметка времени / timestamp
python3 -I tools/check_all.py                             # все модели, Z3, испытания / all models, Z3, tests
```

Для `check_all.py` нужны `numpy`, `scipy`, `z3-solver`, `cryptography` (с ML-DSA). / `check_all.py` needs `numpy`, `scipy`, `z3-solver`, `cryptography` (with ML-DSA).

Отпечаток ключа OpenPGP сверяйте не только по этому файлу, но и по другим независимым источникам: тем же ключом подписан коммит cc3027b публикации v0.1. / Check the OpenPGP fingerprint against independent sources too, not only this file: the same key signed commit cc3027b of the v0.1 publication.

Подпись подтверждает, что файлы опубликованы владельцем этих ключей, а отметка времени — что они существовали не позже отмеченного момента. Ни то ни другое не подтверждает правильность содержания (В-7, K-10). / A signature confirms that the files were published by the holder of these keys, and a timestamp that they existed no later than the stamped moment. Neither confirms that the content is correct (B-7, K-10).

## Предварительные материалы v0.1 / Preliminary materials v0.1

Пакет AEGIS v0.1 (21.10.2026) — предварительные материалы, а не лицензия (О-7). / The AEGIS v0.1 package (21.10.2026) consists of preliminary materials, not a license (F-7).
