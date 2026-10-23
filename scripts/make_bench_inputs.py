"""Writes bench/*/Prover.toml from deterministic keys and signatures made with dilithium-py 1.5.1, each signing the
32-byte message 0x00 0x01 ... 0x1f: Dilithium3 round 3 with key generation driven by the AES-256 CTR DRBG seeded with
48 zero bytes (round 3 signing is deterministic), and ML-DSA-65 with key_derive on 32 zero bytes and an empty context.

Usage: python3 scripts/make_bench_inputs.py   (dilithium-py must be importable)
"""
import hashlib
import os

from dilithium_py.dilithium import Dilithium3
from dilithium_py.ml_dsa import ML_DSA_65

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def arr(data):
    return "[" + ", ".join(str(b) for b in data) + "]"


def matrix(rows):
    return "[" + ", ".join("[" + ", ".join(arr(p) for p in row) + "]" for row in rows) + "]"


def polys(rows):
    return "[" + ", ".join(arr(p) for p in rows) + "]"


def write(package, text):
    open(os.path.join(ROOT, "bench", package, "Prover.toml"), "w").write(text)


def r3_prepared(pk):
    rho, t1 = Dilithium3._unpack_pk(pk)

    a_hat = Dilithium3._expand_matrix_from_seed(rho)

    a_rows = [[a_hat._data[i][j].coeffs for j in range(5)] for i in range(6)]

    t1_hat = t1.scale(1 << 13).to_ntt()

    return Dilithium3._h(pk, 32), a_rows, [p.coeffs for row in t1_hat._data for p in row]


def mldsa_prepared(pk):
    rho, t1 = ML_DSA_65._unpack_pk(pk)

    a_hat = ML_DSA_65._expand_matrix_from_seed(rho)

    a_rows = [[a_hat._data[i][j].coeffs for j in range(5)] for i in range(6)]

    t1_hat = t1.scale(1 << 13).to_ntt()

    return ML_DSA_65._h(pk, 64), a_rows, [p.coeffs for row in t1_hat._data for p in row]


def main():
    msg = bytes(range(32))

    Dilithium3.set_drbg_seed(bytes(48))

    pk, sk = Dilithium3.keygen()

    sig = Dilithium3.sign(sk, msg)

    assert Dilithium3.verify(pk, msg, sig)

    tr, a_rows, t_rows = r3_prepared(pk)

    prepared = f"tr = {arr(tr)}\na_hat = {matrix(a_rows)}\nt1_hat = {polys(t_rows)}\n"

    write("r3_verify_prepared", prepared + f"msg = {arr(msg)}\nsig = {arr(sig)}\n")

    write("r3_verify", f"pk = {arr(pk)}\nmsg = {arr(msg)}\nsig = {arr(sig)}\n")

    write("r3_prepare_key", f"pk = {arr(pk)}\n")

    write("r3_key_commitment", prepared)

    mpk, msk = ML_DSA_65.key_derive(bytes(32))

    mmsg = msg

    msig = ML_DSA_65.sign(msk, mmsg, ctx=b"", deterministic=True)

    assert ML_DSA_65.verify(mpk, mmsg, msig, ctx=b"")

    tr, a_rows, t_rows = mldsa_prepared(mpk)

    mprepared = f"tr = {arr(tr)}\na_hat = {matrix(a_rows)}\nt1_hat = {polys(t_rows)}\n"

    write("mldsa65_verify_prepared", mprepared + f"msg = {arr(mmsg)}\nsig = {arr(msig)}\n")

    write("mldsa65_verify", f"pk = {arr(mpk)}\nmsg = {arr(mmsg)}\nsig = {arr(msig)}\n")

    write("mldsa65_prepare_key", f"pk = {arr(mpk)}\n")

    print(f"bench inputs: Dilithium3 round 3 pk sha256 {hashlib.sha256(pk).hexdigest()[:16]}, ML-DSA-65 pk sha256 {hashlib.sha256(mpk).hexdigest()[:16]}")


if __name__ == "__main__":
    main()
