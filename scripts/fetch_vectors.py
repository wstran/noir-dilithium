"""Builds testdata/*.json from the official vector files.

Inputs (paths given on the command line):
  --kat       PQCsignKAT_Dilithium3.rsp produced by the pq-crystals reference at tag v3.1 (scripts/build_kat_r3.sh)
  --acvp      internalProjection.json from usnistgov/ACVP-Server gen-val/json-files/ML-DSA-sigVer-FIPS204
  --prepared  also write prepared_keys.json for the public keys of the first KAT vectors

Every vector is cross-checked with dilithium-py 1.5.1 before it is written.
"""
import argparse
import hashlib
import json
import sys

from dilithium_py.dilithium import Dilithium3
from dilithium_py.ml_dsa import ML_DSA_65

SIG_BYTES = 3293

PREPARED_COUNT = 6


def sha256_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def read_kat(path):
    entries = []

    current = {}

    for line in open(path):
        line = line.strip()

        if " = " not in line:
            continue

        key, value = line.split(" = ", 1)

        current[key] = value

        if key == "sm":
            entries.append(current)

            current = {}

    out = []

    for e in entries:
        mlen = int(e["mlen"])

        sm = bytes.fromhex(e["sm"])

        sig, msg = sm[:SIG_BYTES], sm[SIG_BYTES:]

        assert len(msg) == mlen and msg == bytes.fromhex(e["msg"])

        pk = bytes.fromhex(e["pk"])

        assert Dilithium3.verify(pk, msg, sig), f"dilithium-py rejects KAT {e['count']}"

        out.append({"count": int(e["count"]), "pk": pk.hex(), "msg": msg.hex(), "sig": sig.hex()})

    return out


def mldsa_verify_mu(pk, mu, sig):
    """ML-DSA.Verify_internal with an external mu, assembled from dilithium-py 1.5.1 internals."""
    s = ML_DSA_65

    rho, t1 = s._unpack_pk(pk)

    try:
        c_tilde, z, h = s._unpack_sig(sig)
    except ValueError:
        return False

    if h.sum_hint() > s.omega or z.check_norm_bound(s.gamma_1 - s.beta):
        return False

    a_hat = s._expand_matrix_from_seed(rho)

    c = s.R.sample_in_ball(c_tilde, s.tau).to_ntt()

    w = ((a_hat @ z.to_ntt()) - t1.scale(1 << s.d).to_ntt().scale(c)).from_ntt()

    w1 = h.use_hint(w, 2 * s.gamma_2).bit_pack_w(s.gamma_2)

    return c_tilde == s._h(mu + w1, s.c_tilde_bytes)


def read_acvp(path):
    data = json.load(open(path))

    out = []

    for group in data["testGroups"]:
        if group["parameterSet"] != "ML-DSA-65" or group.get("preHash") == "preHash":
            continue

        interface = group["signatureInterface"]

        external_mu = bool(group.get("externalMu"))

        for t in group["tests"]:
            pk = bytes.fromhex(t["pk"])

            sig = bytes.fromhex(t["signature"])

            entry = {"tgId": group["tgId"], "tcId": t["tcId"], "interface": interface, "externalMu": external_mu,
                     "testPassed": t["testPassed"], "reason": t["reason"], "pk": pk.hex(), "sig": sig.hex()}

            if external_mu:
                mu = bytes.fromhex(t["mu"])

                got = mldsa_verify_mu(pk, mu, sig)

                entry["mu"] = mu.hex()
            elif interface == "internal":
                msg = bytes.fromhex(t["message"])

                got = ML_DSA_65._verify_internal(pk, msg, sig)

                entry["msg"] = msg.hex()
            else:
                msg = bytes.fromhex(t["message"])

                ctx = bytes.fromhex(t["context"])

                got = ML_DSA_65.verify(pk, msg, sig, ctx=ctx)

                entry["msg"] = msg.hex()

                entry["ctx"] = ctx.hex()

            assert got == t["testPassed"], f"dilithium-py disagrees with ACVP on tcId {t['tcId']}"

            out.append(entry)

    return out


def prepared_keys(kat_path):
    """tr (32 and 64 bytes), A_hat and NTT(t1 * 2^13) of the public keys of the first KAT vectors, from dilithium-py."""
    vectors = json.load(open(kat_path))["vectors"][:PREPARED_COUNT]

    out = []

    for pk_hex in dict.fromkeys(v["pk"] for v in vectors):
        pk = bytes.fromhex(pk_hex)

        rho, t1 = Dilithium3._unpack_pk(pk)

        a_hat = Dilithium3._expand_matrix_from_seed(rho)

        a_rows = [[a_hat._data[i][j].coeffs for j in range(5)] for i in range(6)]

        m_hat = ML_DSA_65._expand_matrix_from_seed(rho)

        assert a_rows == [[m_hat._data[i][j].coeffs for j in range(5)] for i in range(6)]

        t1_hat = t1.scale(1 << 13).to_ntt()

        t_rows = [p.coeffs for row in t1_hat._data for p in row]

        out.append({"pk": pk_hex, "tr32": Dilithium3._h(pk, 32).hex(), "tr64": ML_DSA_65._h(pk, 64).hex(), "a_hat": a_rows, "t1_hat": t_rows})

    return out


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--kat")

    ap.add_argument("--acvp")

    ap.add_argument("--acvp-commit", default="")

    ap.add_argument("--prepared", action="store_true")

    ap.add_argument("--out", required=True)

    args = ap.parse_args()

    if args.kat:
        vectors = read_kat(args.kat)

        meta = {"source": "PQCgenKAT_sign3 from github.com/pq-crystals/dilithium tag v3.1 (ref)", "rsp_sha256": sha256_file(args.kat), "count": len(vectors)}

        json.dump({"meta": meta, "vectors": vectors}, open(f"{args.out}/kat_dilithium3_r3.json", "w"), indent=0)

        print(f"KAT: {len(vectors)} vectors, all accepted by dilithium-py; rsp sha256 {meta['rsp_sha256']}")

    if args.acvp:
        vectors = read_acvp(args.acvp)

        meta = {"source": "github.com/usnistgov/ACVP-Server gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json", "commit": args.acvp_commit, "sha256": sha256_file(args.acvp), "selection": "ML-DSA-65, pure and internal interfaces (external mu included), HashML-DSA groups excluded", "count": len(vectors)}

        json.dump({"meta": meta, "vectors": vectors}, open(f"{args.out}/acvp_mldsa65_sigver.json", "w"), indent=0)

        passed = sum(1 for v in vectors if v["testPassed"])

        print(f"ACVP: {len(vectors)} ML-DSA-65 vectors ({passed} valid), dilithium-py agrees on all")

    if args.prepared:
        keys = prepared_keys(f"{args.out}/kat_dilithium3_r3.json")

        meta = {"source": f"dilithium-py 1.5.1: tr = H(pk, 32) and H(pk, 64), A_hat = ExpandA(rho), t1_hat = NTT(t1 * 2^13) for the public keys of KAT vectors 0 to {PREPARED_COUNT - 1} in kat_dilithium3_r3.json", "count": len(keys)}

        json.dump({"meta": meta, "keys": keys}, open(f"{args.out}/prepared_keys.json", "w"), separators=(",", ":"))

        print(f"prepared keys: {len(keys)} keys")


if __name__ == "__main__":
    sys.exit(main())
