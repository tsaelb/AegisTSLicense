#!/usr/bin/env python3
"""
AEGIS — постквантовая подпись файлов (ML-DSA-65, FIPS 204), вторая подпись рядом с классической (В-1, О-2).

Закрытый ключ создаётся и хранится только на компьютере публикующего, зашифрованным паролем,
вне папки репозитория. В репозиторий попадает только открытый ключ.

Нужна библиотека cryptography с поддержкой ML-DSA (версия 47 или новее).

  python3 tools/pq_sign.py keygen ~/.aegis-pq/aegis_mldsa65 keys/aegis_mldsa65.pub
  python3 tools/pq_sign.py sign   ~/.aegis-pq/aegis_mldsa65 SHA512SUMS SHA3-512SUMS
  python3 tools/pq_sign.py verify keys/aegis_mldsa65.pub    SHA512SUMS SHA3-512SUMS

sign пишет рядом с каждым файлом <файл>.mldsa65.sig; verify проверяет их.
"""
import getpass, os, sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric import mldsa

CONTEXT = b"AEGIS file signature"   # контекст ML-DSA: подпись не перепутать с подписью для другой цели


def keygen(priv_path, pub_path):
    if os.path.exists(priv_path):
        sys.exit(f"{priv_path} уже существует — не перезаписываю")
    pw = getpass.getpass("Пароль для закрытого ключа: ").encode()
    if pw != getpass.getpass("Ещё раз: ").encode() or len(pw) < 12:
        sys.exit("Пароли не совпали или короче 12 символов")
    k = mldsa.MLDSA65PrivateKey.generate()
    os.makedirs(os.path.dirname(os.path.abspath(priv_path)), mode=0o700, exist_ok=True)
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(k.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.BestAvailableEncryption(pw)))
    os.makedirs(os.path.dirname(os.path.abspath(pub_path)), exist_ok=True)
    with open(pub_path, "wb") as f:
        f.write(k.public_key().public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo))
    print(f"Закрытый ключ: {priv_path} (не публиковать, сделать резервную копию)\nОткрытый ключ: {pub_path}")


def sign(priv_path, files):
    pw = getpass.getpass("Пароль закрытого ключа: ").encode()
    with open(priv_path, "rb") as f:
        k = S.load_pem_private_key(f.read(), password=pw)
    for p in files:
        with open(p, "rb") as f:
            sig = k.sign(f.read(), CONTEXT)
        with open(p + ".mldsa65.sig", "wb") as f:
            f.write(sig)
        print(f"подписано: {p} -> {p}.mldsa65.sig")


def verify(pub_path, files):
    with open(pub_path, "rb") as f:
        pub = S.load_pem_public_key(f.read())
    ok = True
    for p in files:
        try:
            with open(p, "rb") as f, open(p + ".mldsa65.sig", "rb") as g:
                pub.verify(g.read(), f.read(), CONTEXT)
            print(f"верна: {p}")
        except (InvalidSignature, FileNotFoundError) as e:
            ok = False
            print(f"НЕВЕРНА: {p} ({type(e).__name__})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "keygen" and len(sys.argv) == 4:
        keygen(os.path.expanduser(sys.argv[2]), sys.argv[3])
    elif cmd == "sign":
        sign(os.path.expanduser(sys.argv[2]), sys.argv[3:])
    elif cmd == "verify":
        verify(sys.argv[2], sys.argv[3:])
    else:
        sys.exit(__doc__)
