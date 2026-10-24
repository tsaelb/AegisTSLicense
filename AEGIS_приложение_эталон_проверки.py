#!/usr/bin/env python3
"""
AEGIS — Приложение З. Эталонная реализация проверок системы доверия и испытания её поведения.

Статус: рабочий материал. Подготовлено с помощью ИИ по указаниям владельца проекта; требует
независимой проверки специалистом по криптографии. Это не средство защиты, а исполняемое описание
правил: оно показывает, что правила В-1, В-2, В-4, В-7, В-10–В-12 и П-13 можно выполнить кодом и что
код отвергает перечисленные атаки. Свойства подтверждены только испытаниями ниже, не доказаны (С-6).

Нужна библиотека cryptography (Ed25519 и ML-DSA-65, FIPS 204).

ЧТО РЕАЛИЗОВАНО
  * хеши: SHA-512 и SHA3-512 одновременно (В-7), без усечения;
  * двойная подпись держателя: Ed25519 и ML-DSA-65; подпись держателя действительна, только если верны обе (В-1);
  * выпуск: манифест файлов, хеш ядра, хеш предыдущего выпуска, временная отметка, вид операции;
  * проверка пользователем (В-4): >= t верных подписей набора, утверждённого предыдущим выпуском;
    совпадение хеша минимум в 2 каналах, для критических операций — в большинстве каналов и окно свежести;
    выпуск должен продолжать известную пользователю цепочку (защита от отката и развилки);
  * смена набора ключей (В-2), отзыв выпуска (В-10), восстановление набора (В-11: решение и срок 90 дней);
  * записи дел (П-13): цепочка хешей и сверка головы цепочки с каналами;
  * проверяемый жребий (В-12): обязательства, раскрытия, не менее двух внешних значений, пересчёт любым.

ЗАПУСК
  python3 AEGIS_приложение_эталон_проверки.py          # все испытания
"""
import hashlib, json, random, sys
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives import serialization as S

# ---------------------------------------------------------------- хеши (В-7)
def H(b: bytes) -> dict:
    return {"sha512": hashlib.sha512(b).hexdigest(), "sha3_512": hashlib.sha3_512(b).hexdigest()}

def hid(h: dict) -> str:
    """Полный идентификатор по обоим алгоритмам."""
    return "sha512=" + h["sha512"] + ";sha3_512=" + h["sha3_512"]

def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

# ---------------------------------------------------------------- держатели и подписи (В-1)
RAW = (S.Encoding.Raw, S.PublicFormat.Raw)

class Holder:
    def __init__(self, name):
        self.name = name
        self.ed = ed25519.Ed25519PrivateKey.generate()
        self.pq = mldsa.MLDSA65PrivateKey.generate()

    def public(self):
        return {"name": self.name,
                "ed25519": self.ed.public_key().public_bytes(*RAW).hex(),
                "mldsa65": self.pq.public_key().public_bytes(*RAW).hex()}

    def sign(self, msg: bytes):
        return {"name": self.name, "ed25519": self.ed.sign(msg).hex(), "mldsa65": self.pq.sign(msg).hex()}

def holder_sig_valid(pub, sig, msg) -> bool:
    if pub["name"] != sig["name"]:
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub["ed25519"])).verify(bytes.fromhex(sig["ed25519"]), msg)
        mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(pub["mldsa65"])).verify(bytes.fromhex(sig["mldsa65"]), msg)
        return True
    except (InvalidSignature, ValueError):
        return False

def keyset(holders, t):
    n = len(holders)
    if not (2 * t > n):
        raise ValueError("t должно быть больше половины n (В-1)")
    return {"t": t, "holders": [h.public() for h in holders]}

def count_valid(ks, sigs, msg) -> int:
    pubs = {p["name"]: p for p in ks["holders"]}
    ok = set()
    for s in sigs:
        p = pubs.get(s["name"])
        if p and holder_sig_valid(p, s, msg):
            ok.add(s["name"])          # один держатель — одна подпись
    return len(ok)

# ---------------------------------------------------------------- выпуск
CRITICAL = {"keyset_change", "revocation", "recovery"}

def make_release(prev, files: dict, core_id: str, time: str, op="release", new_keyset=None, revokes=None, recovery=None):
    body = {"kind": "AEGIS-RELEASE", "op": op, "prev": prev["id"] if prev else None, "time": time,
            "core": core_id, "files": {p: H(c) for p, c in sorted(files.items())}}
    if new_keyset is not None:
        body["new_keyset"] = new_keyset
    if revokes is not None:
        body["revokes"] = revokes
    if recovery is not None:
        body["recovery"] = recovery
    msg = canon(body)
    return {"body": body, "id": hid(H(msg)), "msg": msg, "sigs": []}

def sign_release(rel, holders):
    rel["sigs"] = [h.sign(rel["msg"]) for h in holders]
    return rel

class Verifier:
    """Состояние пользователя: известная голова цепочки, действующий набор ключей, отозванные выпуски (В-4)."""
    def __init__(self, genesis_keyset, freshness=timedelta(days=14)):
        self.keyset = genesis_keyset
        self.head = None
        self.head_time = None
        self.revoked = set()
        self.freshness = freshness

    def check(self, rel, channels: dict, now: datetime):
        b = rel["body"]
        if hid(H(canon(b))) != rel["id"]:
            return False, "манифест не соответствует идентификатору"
        if not self.trusted(rel["id"]):
            return False, "выпуск отозван (В-10)"
        # цепочка: только продолжение известной головы (откат и развилка отвергаются)
        if b["prev"] != self.head:
            return False, "не продолжает известную цепочку (откат или развилка)"
        t = parse_time(b["time"])
        if self.head_time and t <= self.head_time:
            return False, "временная отметка не позже предыдущей"
        if t > now + timedelta(minutes=5):
            return False, "временная отметка в будущем"
        # каналы
        seen = sum(1 for v in channels.values() if v == rel["id"])
        critical = b["op"] in CRITICAL
        need = len(channels) // 2 + 1 if critical else 2
        if seen < need:
            return False, f"совпадение в {seen} каналах из {len(channels)}, нужно {need}"
        if critical and now - t > self.freshness:
            return False, "критическая операция вне окна свежести"
        # подписи
        if b["op"] == "recovery":
            r = b["recovery"]
            if r.get("decision") != "approved" or now < parse_time(r["decided"]) + timedelta(days=90):
                return False, "восстановление: нет утверждённого решения или не прошло 90 дней (В-11)"
            signer_set = b["new_keyset"]
        else:
            signer_set = self.keyset
        v = count_valid(signer_set, rel["sigs"], rel["msg"])
        if v < signer_set["t"]:
            return False, f"верных подписей {v}, нужно {signer_set['t']}"
        if b["op"] == "keyset_change":
            nk = b["new_keyset"]
            if not (2 * nk["t"] > len(nk["holders"])):
                return False, "новый набор нарушает t > n/2"
        return True, "принят"

    def trusted(self, release_id) -> bool:
        """Можно ли и дальше доверять ранее принятому выпуску (отозванный — нельзя, В-10)."""
        if release_id in self.revoked:
            return False
        return True

    def accept(self, rel, channels, now):
        ok, why = self.check(rel, channels, now)
        if ok:
            b = rel["body"]
            self.head, self.head_time = rel["id"], parse_time(b["time"])
            if b["op"] in ("keyset_change", "recovery"):
                self.keyset = b["new_keyset"]
            if b["op"] == "revocation":
                self.revoked.update(b["revokes"])
        return ok, why

# ---------------------------------------------------------------- записи дел (П-13)
def append_record(chain, content: dict, time: str):
    prev = chain[-1]["id"] if chain else None
    body = {"prev": prev, "time": time, "content": content}
    chain.append({"body": body, "id": hid(H(canon(body)))})
    return chain

def verify_chain(chain, anchored_heads: dict):
    prev = None
    for r in chain:
        if r["body"]["prev"] != prev or hid(H(canon(r["body"]))) != r["id"]:
            return False, "нарушена связь записей"
        prev = r["id"]
    ids = {r["id"] for r in chain}
    agree = sum(1 for h in anchored_heads.values() if h in ids)
    if agree < len(anchored_heads) // 2 + 1:
        return False, "опубликованная голова цепочки не найдена в записи (переписана история)"
    return True, "целостна"

# ---------------------------------------------------------------- жребий (В-12)
def commit(value: bytes):
    return hid(H(b"AEGIS-COMMIT" + value))

def lottery(candidates, commits, reveals, beacons, k):
    if len(beacons) < 2:
        raise ValueError("нужно не менее двух внешних значений (В-12)")
    valid = sorted(c for c in candidates if c in reveals and commit(reveals[c]) == commits.get(c))
    seed_material = b"".join(c.encode() + reveals[c] for c in valid) + b"".join(b.encode() for b in sorted(beacons))
    seed = int(hashlib.sha3_512(b"AEGIS-LOT" + seed_material).hexdigest(), 16)
    rng = random.Random(seed)
    order = valid[:]
    rng.shuffle(order)
    return order[:k], sorted(set(candidates) - set(valid))

# ---------------------------------------------------------------- испытания
def run_tests():
    results = []
    def case(name, cond):
        results.append((name, bool(cond)))

    T0 = datetime(2027, 1, 1, tzinfo=timezone.utc)
    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    holders = [Holder(f"h{i:02d}") for i in range(17)]
    KS = keyset(holders, 9)
    core_id = "core-test"
    chans = lambda rid, n=6, good=6: {f"c{i}": (rid if i < good else "другое") for i in range(n)}

    V = Verifier(KS)
    r1 = sign_release(make_release(None, {"a.txt": b"A"}, core_id, iso(T0)), holders[:9])
    ok, why = V.accept(r1, chans(r1["id"], good=2), T0 + timedelta(hours=1))
    case("1. выпуск с 9 из 17 и совпадением в 2 каналах принят", ok)

    r2 = sign_release(make_release(r1, {"a.txt": b"A2"}, core_id, iso(T0 + timedelta(days=1))), holders[:8])
    case("2. 8 из 17 подписей отвергнуто", not V.check(r2, chans(r2["id"]), T0 + timedelta(days=1, hours=1))[0])

    r3 = sign_release(make_release(r1, {"a.txt": b"A3"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    r3["sigs"] = r3["sigs"][:8] + [r3["sigs"][0]] * 3
    case("3. повтор подписи одного держателя не засчитывается", not V.check(r3, chans(r3["id"]), T0 + timedelta(days=1, hours=1))[0])

    r4 = sign_release(make_release(r1, {"a.txt": b"A4"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    for s in r4["sigs"]:
        s["mldsa65"] = r1["sigs"][0]["mldsa65"]       # верна только классическая часть
    case("4. подпись без верной постквантовой части отвергнута", not V.check(r4, chans(r4["id"]), T0 + timedelta(days=1, hours=1))[0])

    r5 = sign_release(make_release(r1, {"a.txt": b"A5"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    r5["body"]["files"]["a.txt"] = H("подмена".encode())
    case("5. подмена файла после подписи обнаружена", not V.check(r5, chans(r5["id"]), T0 + timedelta(days=1, hours=1))[0])

    r6 = sign_release(make_release(r1, {"a.txt": b"A6"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    case("6. совпадение только в 1 канале отвергнуто", not V.check(r6, chans(r6["id"], good=1), T0 + timedelta(days=1, hours=1))[0])
    ok, _ = V.accept(r6, chans(r6["id"], good=2), T0 + timedelta(days=1, hours=1))
    case("7. продолжение цепочки принято", ok)

    case("8. повторная подача старого выпуска (откат) отвергнута", not V.check(r1, chans(r1["id"]), T0 + timedelta(days=2))[0])
    fork = sign_release(make_release(r1, {"a.txt": b"F"}, core_id, iso(T0 + timedelta(days=2))), holders[8:])
    case("9. развилка от старой головы отвергнута, даже с 9 подписями", not V.check(fork, chans(fork["id"]), T0 + timedelta(days=2, hours=1))[0])

    new_h = [Holder(f"n{i:02d}") for i in range(17)]
    NK = keyset(new_h, 9)
    kc = sign_release(make_release(r6, {}, core_id, iso(T0 + timedelta(days=3)), op="keyset_change", new_keyset=NK), holders[:9])
    case("10. смена ключей при совпадении в 3 из 6 каналов отвергнута (нужно большинство)", not V.check(kc, chans(kc["id"], good=3), T0 + timedelta(days=3, hours=1))[0])
    case("11. смена ключей вне окна свежести отвергнута", not V.check(kc, chans(kc["id"], good=4), T0 + timedelta(days=30))[0])
    ok, _ = V.accept(kc, chans(kc["id"], good=4), T0 + timedelta(days=3, hours=1))
    case("12. смена ключей подписями 9 из текущего набора и большинством каналов принята", ok)
    old = sign_release(make_release(kc, {"a.txt": b"O"}, core_id, iso(T0 + timedelta(days=4))), holders[:17])
    case("13. все 17 прежних ключей после смены не подписывают выпуск", not V.check(old, chans(old["id"]), T0 + timedelta(days=4, hours=1))[0])
    r7 = sign_release(make_release(kc, {"a.txt": b"A7"}, core_id, iso(T0 + timedelta(days=4))), new_h[:9])
    ok, _ = V.accept(r7, chans(r7["id"], good=2), T0 + timedelta(days=4, hours=1))
    case("14. выпуск новым набором принят", ok)
    try:
        keyset(new_h, 8); bad = False
    except ValueError:
        bad = True
    case("15. набор с t <= n/2 (8 из 17) нельзя создать", bad)

    rv = sign_release(make_release(r7, {}, core_id, iso(T0 + timedelta(days=5)), op="revocation", revokes=[r7["id"]]), new_h[:9])
    ok, _ = V.accept(rv, chans(rv["id"], good=4), T0 + timedelta(days=5, hours=1))
    case("16. после отзыва выпуску больше не доверяют, остальным — доверяют", ok and not V.trusted(r7["id"]) and V.trusted(r6["id"]))

    rec_h = [Holder(f"r{i:02d}") for i in range(17)]
    RK = keyset(rec_h, 9)
    dec = iso(T0 + timedelta(days=6))
    early = sign_release(make_release(rv, {}, core_id, iso(T0 + timedelta(days=50)), op="recovery", new_keyset=RK,
                                      recovery={"decision": "approved", "decided": dec}), rec_h[:9])
    case("17. восстановление раньше 90 дней после решения отвергнуто", not V.check(early, chans(early["id"], good=4), T0 + timedelta(days=50, hours=1))[0])
    late = sign_release(make_release(rv, {}, core_id, iso(T0 + timedelta(days=97)), op="recovery", new_keyset=RK,
                                     recovery={"decision": "approved", "decided": dec}), rec_h[:9])
    ok, _ = V.accept(late, chans(late["id"], good=4), T0 + timedelta(days=97, hours=1))
    case("18. восстановление после 90 дней, большинство каналов, свежая отметка — принято", ok)

    ch = []
    for i in range(20):
        append_record(ch, {"step": i}, iso(T0 + timedelta(hours=i)))
    heads = {f"c{i}": ch[-1]["id"] for i in range(6)}
    case("19. целостная запись дела проверяется", verify_chain(ch, heads)[0])
    tampered = json.loads(json.dumps(ch))
    tampered[5]["body"]["content"] = {"step": "подмена"}
    case("20. изменение одной записи обнаружено", not verify_chain(tampered, heads)[0])
    rewritten = []
    for i in range(20):
        append_record(rewritten, {"step": i if i != 5 else "подмена"}, iso(T0 + timedelta(hours=i)))
    case("21. полная перезапись цепочки ведущим запись обнаружена по опубликованной голове", not verify_chain(rewritten, heads)[0])

    cands = [f"p{i:02d}" for i in range(30)]
    secrets = {c: hashlib.sha256(c.encode() + b"s").digest() for c in cands}
    commits = {c: commit(v) for c, v in secrets.items()}
    beacons = ["btc:00000000000000000001", "drand:abcdef"]
    sel1, _ = lottery(cands, commits, secrets, beacons, 7)
    sel2, _ = lottery(list(reversed(cands)), commits, secrets, beacons, 7)
    case("22. жребий пересчитывается любым одинаково", sel1 == sel2 and len(sel1) == 7)
    partial = {c: v for c, v in secrets.items() if c != "p03"}
    _, excluded = lottery(cands, commits, partial, beacons, 7)
    case("23. нераскрывший исключён и записан", excluded == ["p03"])
    forged = dict(secrets); forged["p04"] = "другое".encode()
    _, excluded = lottery(cands, commits, forged, beacons, 7)
    case("24. раскрытие, не совпавшее с обязательством, исключено", "p04" in excluded)
    try:
        lottery(cands, commits, secrets, beacons[:1], 7); one = False
    except ValueError:
        one = True
    case("25. жребий с одним внешним значением отвергнут", one)
    sel3, _ = lottery(cands, commits, secrets, ["btc:00000000000000000002", "drand:abcdef"], 7)
    case("26. другое внешнее значение даёт другой результат", sel3 != sel1)

    # случайные атаки: любая перестановка подписей и подмножества 9 держателей принимаются,
    # любые 8 — нет; любое изменение байта манифеста отвергается
    rnd = random.Random(2027)
    ok_all = True
    for _ in range(25):
        Vt = Verifier(KS)
        subset = rnd.sample(holders, rnd.choice([8, 9, 10]))
        r = sign_release(make_release(None, {"f": bytes([rnd.randrange(256)])}, core_id, iso(T0)), subset)
        rnd.shuffle(r["sigs"])
        got = Vt.check(r, chans(r["id"], good=rnd.randint(2, 6)), T0 + timedelta(hours=1))[0]
        ok_all &= (got == (len(subset) >= 9))
        m = bytearray(r["msg"]); i = rnd.randrange(len(m)); m[i] ^= 1
        r_bad = dict(r); r_bad["msg"] = bytes(m)
        ok_all &= count_valid(KS, r["sigs"], bytes(m)) == 0
    case("27. 25 случайных испытаний: порог соблюдается, изменение любого бита разрушает все подписи", ok_all)

    width = max(len(n) for n, _ in results)
    for n, r in results:
        print(f"  [{'OK ' if r else 'ОШИБКА'}] {n}")
    failed = [n for n, r in results if not r]
    print(f"Испытаний: {len(results)}, не пройдено: {len(failed)}")
    print("Пройдены все испытания." if not failed else "ЕСТЬ НЕПРОЙДЕННЫЕ ИСПЫТАНИЯ.")
    return not failed

if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
