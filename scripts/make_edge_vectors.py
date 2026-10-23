"""Builds testdata/edge_vectors.json: valid signatures made with dilithium-py 1.5.1 from fixed seeds that reach
encoding edge cases the official vectors miss: ML-DSA-65 with an empty and with a 255-byte context, a signature
with a hint polynomial that has no hints, and a signature with the largest allowed number of hints (omega = 55).

Messages are counter values (4 bytes, big-endian) followed by 28 zero bytes; the search stops at the first match.

Usage: python3 scripts/make_edge_vectors.py [max_tries]   (dilithium-py and pycryptodome must be importable)
"""
import json
import os
import sys

from dilithium_py.dilithium import Dilithium3
from dilithium_py.ml_dsa import ML_DSA_65

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OMEGA = 55


def hint_counts(sig):
    h = sig[len(sig) - 61:]

    offsets = list(h[OMEGA:])

    return offsets[5], [offsets[0]] + [offsets[i] - offsets[i - 1] for i in range(1, 6)]


def search(sign, want, tries):
    """First counter message whose signature satisfies want(total hints, per-polynomial hints)."""
    for n in range(tries):
        msg = n.to_bytes(4, "big") + bytes(28)

        sig = sign(msg)

        total, per = hint_counts(sig)

        if want(total, per):
            return msg, sig, n

    return None


def main():
    tries = int(sys.argv[1]) if len(sys.argv) > 1 else 4000

    Dilithium3.set_drbg_seed(bytes(48))

    r3_pk, r3_sk = Dilithium3.keygen()

    ml_pk, ml_sk = ML_DSA_65.key_derive(bytes(32))

    r3_sign = lambda m: Dilithium3.sign(r3_sk, m)

    ml_sign = lambda m: ML_DSA_65.sign(ml_sk, m, ctx=b"", deterministic=True)

    out = []

    for ctx in (b"", bytes(range(255))):
        msg = bytes(range(32))

        sig = ML_DSA_65.sign(ml_sk, msg, ctx=ctx, deterministic=True)

        assert ML_DSA_65.verify(ml_pk, msg, sig, ctx=ctx)

        out.append({"name": f"mldsa65_context_{len(ctx)}_bytes", "mode": "ml_dsa_65", "pk": ml_pk.hex(), "msg": msg.hex(), "ctx": ctx.hex(), "sig": sig.hex()})

    cases = (("empty_hint_polynomial", lambda total, per: min(per) == 0), ("omega_hints", lambda total, per: total == OMEGA))

    for name, want in cases:
        for mode, pk, sign, verify in (("dilithium3_r3", r3_pk, r3_sign, lambda m, s: Dilithium3.verify(r3_pk, m, s)), ("ml_dsa_65", ml_pk, ml_sign, lambda m, s: ML_DSA_65.verify(ml_pk, m, s, ctx=b""))):
            found = search(sign, want, tries)

            if found is None:
                print(f"{mode} {name}: none in {tries} messages")

                continue

            msg, sig, n = found

            assert verify(msg, sig)

            entry = {"name": f"{mode}_{name}", "mode": mode, "pk": pk.hex(), "msg": msg.hex(), "sig": sig.hex()}

            if mode == "ml_dsa_65":
                entry["ctx"] = ""

            out.append(entry)

            print(f"{mode} {name}: message counter {n}")

    meta = {"source": "dilithium-py 1.5.1; Dilithium3 round 3 key from the AES-256 CTR DRBG seeded with 48 zero bytes, ML-DSA-65 key from key_derive(32 zero bytes), deterministic signing", "count": len(out)}

    json.dump({"meta": meta, "vectors": out}, open(os.path.join(ROOT, "testdata", "edge_vectors.json"), "w"), indent=0)

    print(f"wrote {len(out)} edge vectors")


if __name__ == "__main__":
    main()
