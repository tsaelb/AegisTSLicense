"""Мутационная проверка испытаний Приложения З: каждая ослабленная версия правил должна провалить хотя бы одно испытание."""
import subprocess, sys, os, tempfile
src = open(sys.argv[1], encoding="utf-8").read()
M = {
 "порог подписей t-1": ('if v < signer_set["t"]:', 'if v < signer_set["t"] - 1:'),
 "без постквантовой подписи": ('        mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(pub["mldsa65"])).verify(bytes.fromhex(sig["mldsa65"]), msg)\n', ''),
 "повтор подписи засчитывается": ('ok.add(s["name"])', 'ok.add(s["name"] + str(len(ok)))'),
 "без проверки цепочки": ('if b["prev"] != self.head:', 'if False:'),
 "один канал достаточен": ('else 2', 'else 1'),
 "критические без большинства": ('len(channels) // 2 + 1 if critical', '2 if critical'),
 "без окна свежести": ('if critical and now - t > self.freshness:', 'if False:'),
 "без срока 90 дней": ('now < parse_time(r["decided"]) + timedelta(days=90)', 'False'),
 "t <= n/2 допустимо": ('if not (2 * t > n):', 'if False:'),
 "без сверки головы записи": ('if agree < len(anchored_heads) // 2 + 1:', 'if False:'),
 "один внешний источник": ('if len(beacons) < 2:', 'if len(beacons) < 1:'),
 "раскрытие без сверки обязательства": ('c in reveals and commit(reveals[c]) == commits.get(c)', 'c in reveals'),
 "отзыв не действует": ('        if release_id in self.revoked:\n            return False\n', ''),
}
d = tempfile.mkdtemp()
alive = []
for name, (a, b) in M.items():
    assert src.count(a) >= 1, name
    p = os.path.join(d, "m.py"); open(p, "w", encoding="utf-8").write(src.replace(a, b, 1))
    r = subprocess.run([sys.executable, "-I", p], capture_output=True, text=True)
    killed = r.returncode != 0
    print(f"  {'убита' if killed else 'ВЫЖИЛА'}: {name}")
    if not killed: alive.append(name)
print(f"Мутаций: {len(M)}, выжило: {len(alive)}")
sys.exit(1 if alive else 0)
