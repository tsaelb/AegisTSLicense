#!/usr/bin/env python3
"""
AEGIS — Appendix H. Reference implementation of the checks of the Trust System and tests of its behaviour.
English version of «AEGIS_приложение_эталон_проверки.py»; the code and tests are the same.

Status: working material. Prepared with the help of AI according to the instructions of the project owner; requires
independent review by a cryptographer. This is not a security tool but an executable description of the
rules: it shows that rules B-1, B-2, B-4, B-7, B-10–B-12 and P-13 can be carried out in code and that the
code rejects the attacks listed. The properties are confirmed only by the tests below, not proven (C-6).

Requires the cryptography library (Ed25519 and ML-DSA-65, FIPS 204).

WHAT IS IMPLEMENTED
  * hashes: SHA-512 and SHA3-512 together (B-7), without truncation;
  * a holder's dual signature: Ed25519 and ML-DSA-65; a holder's signature is valid only if both are valid (B-1);
  * a release: manifest of files, hash of the Core, hash of the previous release, timestamp, type of operation;
  * user verification (B-4): >= t valid signatures of the set approved by the previous release;
    hash match in at least 2 channels, for critical operations — in a majority of channels and a freshness window;
    a release must continue the chain known to the user (protection against rollback and forks);
  * key set rotation (B-2), release revocation (B-10), recovery of the set (B-11: decision and a 90-day period);
  * case records (P-13): a hash chain and checking the head of the chain against the channels;
  * verifiable lot (B-12): commitments, reveals, at least two external values, recomputation by anyone.

RUN
  python3 AEGIS_appendix_H_reference_verification.py          # all tests
"""
import hashlib, json, random, sys
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives import serialization as S

# ---------------------------------------------------------------- hashes (B-7)
def H(b: bytes) -> dict:
    return {"sha512": hashlib.sha512(b).hexdigest(), "sha3_512": hashlib.sha3_512(b).hexdigest()}

def hid(h: dict) -> str:
    """Full identifier under both algorithms."""
    return "sha512=" + h["sha512"] + ";sha3_512=" + h["sha3_512"]

def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

# ---------------------------------------------------------------- holders and signatures (B-1)
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
        raise ValueError("t must be greater than half of n (B-1)")
    return {"t": t, "holders": [h.public() for h in holders]}

def count_valid(ks, sigs, msg) -> int:
    pubs = {p["name"]: p for p in ks["holders"]}
    ok = set()
    for s in sigs:
        p = pubs.get(s["name"])
        if p and holder_sig_valid(p, s, msg):
            ok.add(s["name"])          # one holder — one signature
    return len(ok)

# ---------------------------------------------------------------- release
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
    """User state: the known head of the chain, the key set in force, revoked releases (B-4)."""
    def __init__(self, genesis_keyset, freshness=timedelta(days=14)):
        self.keyset = genesis_keyset
        self.head = None
        self.head_time = None
        self.revoked = set()
        self.freshness = freshness

    def check(self, rel, channels: dict, now: datetime):
        b = rel["body"]
        if hid(H(canon(b))) != rel["id"]:
            return False, "the manifest does not match the identifier"
        if not self.trusted(rel["id"]):
            return False, "the release is revoked (B-10)"
        # chain: only a continuation of the known head (rollback and forks are rejected)
        if b["prev"] != self.head:
            return False, "does not continue the known chain (rollback or fork)"
        t = parse_time(b["time"])
        if self.head_time and t <= self.head_time:
            return False, "timestamp not later than the previous one"
        if t > now + timedelta(minutes=5):
            return False, "timestamp in the future"
        # channels
        seen = sum(1 for v in channels.values() if v == rel["id"])
        critical = b["op"] in CRITICAL
        need = len(channels) // 2 + 1 if critical else 2
        if seen < need:
            return False, f"match in {seen} channels of {len(channels)}, {need} needed"
        if critical and now - t > self.freshness:
            return False, "critical operation outside the freshness window"
        # signatures
        if b["op"] == "recovery":
            r = b["recovery"]
            if r.get("decision") != "approved" or now < parse_time(r["decided"]) + timedelta(days=90):
                return False, "recovery: no approved decision or 90 days have not passed (B-11)"
            signer_set = b["new_keyset"]
        else:
            signer_set = self.keyset
        v = count_valid(signer_set, rel["sigs"], rel["msg"])
        if v < signer_set["t"]:
            return False, f"valid signatures {v}, {signer_set['t']} needed"
        if b["op"] == "keyset_change":
            nk = b["new_keyset"]
            if not (2 * nk["t"] > len(nk["holders"])):
                return False, "the new set violates t > n/2"
        return True, "accepted"

    def trusted(self, release_id) -> bool:
        """Whether a previously accepted release may still be trusted (a revoked one may not, B-10)."""
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

# ---------------------------------------------------------------- case records (P-13)
def append_record(chain, content: dict, time: str):
    prev = chain[-1]["id"] if chain else None
    body = {"prev": prev, "time": time, "content": content}
    chain.append({"body": body, "id": hid(H(canon(body)))})
    return chain

def verify_chain(chain, anchored_heads: dict):
    prev = None
    for r in chain:
        if r["body"]["prev"] != prev or hid(H(canon(r["body"]))) != r["id"]:
            return False, "the link between records is broken"
        prev = r["id"]
    ids = {r["id"] for r in chain}
    agree = sum(1 for h in anchored_heads.values() if h in ids)
    if agree < len(anchored_heads) // 2 + 1:
        return False, "the published head of the chain is not found in the record (history rewritten)"
    return True, "intact"

# ---------------------------------------------------------------- lot (B-12)
def commit(value: bytes):
    return hid(H(b"AEGIS-COMMIT" + value))

def lottery(candidates, commits, reveals, beacons, k):
    if len(beacons) < 2:
        raise ValueError("at least two external values are needed (B-12)")
    valid = sorted(c for c in candidates if c in reveals and commit(reveals[c]) == commits.get(c))
    seed_material = b"".join(c.encode() + reveals[c] for c in valid) + b"".join(b.encode() for b in sorted(beacons))
    seed = int(hashlib.sha3_512(b"AEGIS-LOT" + seed_material).hexdigest(), 16)
    rng = random.Random(seed)
    order = valid[:]
    rng.shuffle(order)
    return order[:k], sorted(set(candidates) - set(valid))

# ---------------------------------------------------------------- tests
def run_tests():
    results = []
    def case(name, cond):
        results.append((name, bool(cond)))

    T0 = datetime(2027, 1, 1, tzinfo=timezone.utc)
    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    holders = [Holder(f"h{i:02d}") for i in range(17)]
    KS = keyset(holders, 9)
    core_id = "core-test"
    chans = lambda rid, n=6, good=6: {f"c{i}": (rid if i < good else "other") for i in range(n)}

    V = Verifier(KS)
    r1 = sign_release(make_release(None, {"a.txt": b"A"}, core_id, iso(T0)), holders[:9])
    ok, why = V.accept(r1, chans(r1["id"], good=2), T0 + timedelta(hours=1))
    case("1. a release with 9 of 17 and a match in 2 channels is accepted", ok)

    r2 = sign_release(make_release(r1, {"a.txt": b"A2"}, core_id, iso(T0 + timedelta(days=1))), holders[:8])
    case("2. 8 of 17 signatures is rejected", not V.check(r2, chans(r2["id"]), T0 + timedelta(days=1, hours=1))[0])

    r3 = sign_release(make_release(r1, {"a.txt": b"A3"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    r3["sigs"] = r3["sigs"][:8] + [r3["sigs"][0]] * 3
    case("3. a repeated signature of one holder is not counted", not V.check(r3, chans(r3["id"]), T0 + timedelta(days=1, hours=1))[0])

    r4 = sign_release(make_release(r1, {"a.txt": b"A4"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    for s in r4["sigs"]:
        s["mldsa65"] = r1["sigs"][0]["mldsa65"]       # only the classical part is valid
    case("4. a signature without a valid post-quantum part is rejected", not V.check(r4, chans(r4["id"]), T0 + timedelta(days=1, hours=1))[0])

    r5 = sign_release(make_release(r1, {"a.txt": b"A5"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    r5["body"]["files"]["a.txt"] = H("substituted".encode())
    case("5. substitution of a file after signing is detected", not V.check(r5, chans(r5["id"]), T0 + timedelta(days=1, hours=1))[0])

    r6 = sign_release(make_release(r1, {"a.txt": b"A6"}, core_id, iso(T0 + timedelta(days=1))), holders[:9])
    case("6. a match in only 1 channel is rejected", not V.check(r6, chans(r6["id"], good=1), T0 + timedelta(days=1, hours=1))[0])
    ok, _ = V.accept(r6, chans(r6["id"], good=2), T0 + timedelta(days=1, hours=1))
    case("7. a continuation of the chain is accepted", ok)

    case("8. resubmitting an old release (rollback) is rejected", not V.check(r1, chans(r1["id"]), T0 + timedelta(days=2))[0])
    fork = sign_release(make_release(r1, {"a.txt": b"F"}, core_id, iso(T0 + timedelta(days=2))), holders[8:])
    case("9. a fork from an old head is rejected, even with 9 signatures", not V.check(fork, chans(fork["id"]), T0 + timedelta(days=2, hours=1))[0])

    new_h = [Holder(f"n{i:02d}") for i in range(17)]
    NK = keyset(new_h, 9)
    kc = sign_release(make_release(r6, {}, core_id, iso(T0 + timedelta(days=3)), op="keyset_change", new_keyset=NK), holders[:9])
    case("10. key rotation with a match in 3 of 6 channels is rejected (a majority is needed)", not V.check(kc, chans(kc["id"], good=3), T0 + timedelta(days=3, hours=1))[0])
    case("11. key rotation outside the freshness window is rejected", not V.check(kc, chans(kc["id"], good=4), T0 + timedelta(days=30))[0])
    ok, _ = V.accept(kc, chans(kc["id"], good=4), T0 + timedelta(days=3, hours=1))
    case("12. key rotation with signatures of 9 of the current set and a majority of channels is accepted", ok)
    old = sign_release(make_release(kc, {"a.txt": b"O"}, core_id, iso(T0 + timedelta(days=4))), holders[:17])
    case("13. all 17 former keys cannot sign a release after rotation", not V.check(old, chans(old["id"]), T0 + timedelta(days=4, hours=1))[0])
    r7 = sign_release(make_release(kc, {"a.txt": b"A7"}, core_id, iso(T0 + timedelta(days=4))), new_h[:9])
    ok, _ = V.accept(r7, chans(r7["id"], good=2), T0 + timedelta(days=4, hours=1))
    case("14. a release by the new set is accepted", ok)
    try:
        keyset(new_h, 8); bad = False
    except ValueError:
        bad = True
    case("15. a set with t <= n/2 (8 of 17) cannot be created", bad)

    rv = sign_release(make_release(r7, {}, core_id, iso(T0 + timedelta(days=5)), op="revocation", revokes=[r7["id"]]), new_h[:9])
    ok, _ = V.accept(rv, chans(rv["id"], good=4), T0 + timedelta(days=5, hours=1))
    case("16. after revocation the release is no longer trusted, the others still are", ok and not V.trusted(r7["id"]) and V.trusted(r6["id"]))

    rec_h = [Holder(f"r{i:02d}") for i in range(17)]
    RK = keyset(rec_h, 9)
    dec = iso(T0 + timedelta(days=6))
    early = sign_release(make_release(rv, {}, core_id, iso(T0 + timedelta(days=50)), op="recovery", new_keyset=RK,
                                      recovery={"decision": "approved", "decided": dec}), rec_h[:9])
    case("17. recovery earlier than 90 days after the decision is rejected", not V.check(early, chans(early["id"], good=4), T0 + timedelta(days=50, hours=1))[0])
    late = sign_release(make_release(rv, {}, core_id, iso(T0 + timedelta(days=97)), op="recovery", new_keyset=RK,
                                     recovery={"decision": "approved", "decided": dec}), rec_h[:9])
    ok, _ = V.accept(late, chans(late["id"], good=4), T0 + timedelta(days=97, hours=1))
    case("18. recovery after 90 days, a majority of channels, a fresh timestamp — accepted", ok)

    ch = []
    for i in range(20):
        append_record(ch, {"step": i}, iso(T0 + timedelta(hours=i)))
    heads = {f"c{i}": ch[-1]["id"] for i in range(6)}
    case("19. an intact case record verifies", verify_chain(ch, heads)[0])
    tampered = json.loads(json.dumps(ch))
    tampered[5]["body"]["content"] = {"step": "substituted"}
    case("20. a change to one record is detected", not verify_chain(tampered, heads)[0])
    rewritten = []
    for i in range(20):
        append_record(rewritten, {"step": i if i != 5 else "substituted"}, iso(T0 + timedelta(hours=i)))
    case("21. a full rewrite of the chain by its keeper is detected by the published head", not verify_chain(rewritten, heads)[0])

    cands = [f"p{i:02d}" for i in range(30)]
    secrets = {c: hashlib.sha256(c.encode() + b"s").digest() for c in cands}
    commits = {c: commit(v) for c, v in secrets.items()}
    beacons = ["btc:00000000000000000001", "drand:abcdef"]
    sel1, _ = lottery(cands, commits, secrets, beacons, 7)
    sel2, _ = lottery(list(reversed(cands)), commits, secrets, beacons, 7)
    case("22. anyone recomputes the lot identically", sel1 == sel2 and len(sel1) == 7)
    partial = {c: v for c, v in secrets.items() if c != "p03"}
    _, excluded = lottery(cands, commits, partial, beacons, 7)
    case("23. a non-revealer is excluded and recorded", excluded == ["p03"])
    forged = dict(secrets); forged["p04"] = "other".encode()
    _, excluded = lottery(cands, commits, forged, beacons, 7)
    case("24. a reveal not matching its commitment is excluded", "p04" in excluded)
    try:
        lottery(cands, commits, secrets, beacons[:1], 7); one = False
    except ValueError:
        one = True
    case("25. a lot with a single external value is rejected", one)
    sel3, _ = lottery(cands, commits, secrets, ["btc:00000000000000000002", "drand:abcdef"], 7)
    case("26. a different external value gives a different result", sel3 != sel1)

    # random attacks: any permutation of signatures and any subset of 9 holders is accepted,
    # any 8 are not; any change to a byte of the manifest is rejected
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
    case("27. 25 random tests: the threshold holds, changing any bit breaks all signatures", ok_all)

    width = max(len(n) for n, _ in results)
    for n, r in results:
        print(f"  [{'OK ' if r else 'FAIL'}] {n}")
    failed = [n for n, r in results if not r]
    print(f"Tests: {len(results)}, failed: {len(failed)}")
    print("All tests passed." if not failed else "SOME TESTS FAILED.")
    return not failed

if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
