"""Generates the Noir vector test packages from testdata/*.json into OUT_DIR (outside the repository, because
nargo only builds packages nested under the repository when they are workspace members).

Usage: python3 scripts/gen_tests.py OUT_DIR [--constrained]

By default the vector tests are unconstrained (Brillig) so that every vector runs in minutes; with
--constrained the same tests are emitted as constrained functions and run through ACIR witness generation.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SIG_BYTES = 3293

HINT_START = SIG_BYTES - 61

TAMPERED_COUNT = 30


def arr(data):
    return "[" + ", ".join(str(b) for b in data) + "]"


OUT = None


def write_package(name, body):
    d = os.path.join(OUT, name)

    os.makedirs(os.path.join(d, "src"), exist_ok=True)

    lib = os.path.join(ROOT, "lib")

    open(os.path.join(d, "Nargo.toml"), "w").write(f'[package]\nname = "{name}"\ntype = "lib"\nauthors = [""]\n\n[dependencies]\ndilithium = {{ path = "{lib}" }}\n')

    open(os.path.join(d, "src", "lib.nr"), "w").write(body)


def test_fn(constrained, name, body):
    kind = "fn" if constrained else "unconstrained fn"

    return f"#[test]\n{kind} {name}() {{\n{body}\n}}\n"


def kat_r3(constrained):
    data = json.load(open(os.path.join(ROOT, "testdata", "kat_dilithium3_r3.json")))

    out = [f"// {data['meta']['source']}, rsp sha256 {data['meta']['rsp_sha256']}.\nuse dilithium::dilithium3_r3;\n"]

    for v in data["vectors"]:
        c = v["count"]

        msg = bytes.fromhex(v["msg"])

        out.append(f"global PK_{c}: [u8; 1952] = {arr(bytes.fromhex(v['pk']))};\n")

        out.append(f"global MSG_{c}: [u8; {len(msg)}] = {arr(msg)};\n")

        out.append(f"global SIG_{c}: [u8; 3293] = {arr(bytes.fromhex(v['sig']))};\n")

        out.append(test_fn(constrained, f"kat_{c}", f"    assert(dilithium3_r3::verify(PK_{c}, MSG_{c}, SIG_{c}));"))

    write_package("kat_r3", "\n".join(out))

    return len(data["vectors"])


def acvp(constrained):
    data = json.load(open(os.path.join(ROOT, "testdata", "acvp_mldsa65_sigver.json")))

    out = [f"// {data['meta']['source']} (commit {data['meta']['commit']}, sha256 {data['meta']['sha256']}).\n// {data['meta']['selection']}.\nuse dilithium::ml_dsa_65;\n"]

    for v in data["vectors"]:
        t = v["tcId"]

        expected = "true" if v["testPassed"] else "false"

        out.append(f"// tgId {v['tgId']}, {v['interface']}, externalMu {v['externalMu']}: {v['reason']}.")

        out.append(f"global PK_{t}: [u8; 1952] = {arr(bytes.fromhex(v['pk']))};\n")

        out.append(f"global SIG_{t}: [u8; 3309] = {arr(bytes.fromhex(v['sig']))};\n")

        if v["externalMu"]:
            out.append(f"global MU_{t}: [u8; 64] = {arr(bytes.fromhex(v['mu']))};\n")

            call = f"ml_dsa_65::verify_mu(PK_{t}, MU_{t}, SIG_{t})"
        elif v["interface"] == "internal":
            msg = bytes.fromhex(v["msg"])

            out.append(f"global MSG_{t}: [u8; {len(msg)}] = {arr(msg)};\n")

            call = f"ml_dsa_65::verify_internal(PK_{t}, MSG_{t}, SIG_{t})"
        else:
            msg = bytes.fromhex(v["msg"])

            ctx = bytes.fromhex(v["ctx"])

            out.append(f"global MSG_{t}: [u8; {len(msg)}] = {arr(msg)};\n")

            out.append(f"global CTX_{t}: [u8; {len(ctx)}] = {arr(ctx)};\n")

            call = f"ml_dsa_65::verify(PK_{t}, MSG_{t}, CTX_{t}, SIG_{t})"

        out.append(test_fn(constrained, f"acvp_tc{t}", f"    assert({call} == {expected});"))

    v = next(v for v in data["vectors"] if v["testPassed"] and v["interface"] == "external")

    t = v["tcId"]

    body = f"    let ctx: [u8; 256] = [0; 256];\n\n    assert(!ml_dsa_65::verify(PK_{t}, MSG_{t}, ctx, SIG_{t}));"

    out.append("// FIPS 204 Algorithm 3 rejects contexts longer than 255 bytes.")

    out.append(test_fn(constrained, "context_over_255_bytes", body))

    write_package("acvp_mldsa65", "\n".join(out))

    return len(data["vectors"]) + 1


def tampered_r3(constrained, kat):
    """The first KAT vectors with one byte of c_tilde, z, the hint encoding or the message flipped: verify is false."""
    out = [f"// Tampered copies of the first {TAMPERED_COUNT} vectors of {kat['meta']['source']}.\nuse dilithium::dilithium3_r3;\n"]

    count = 0

    for v in kat["vectors"][:TAMPERED_COUNT]:
        c = v["count"]

        msg = bytes.fromhex(v["msg"])

        out.append(f"global PK_{c}: [u8; 1952] = {arr(bytes.fromhex(v['pk']))};\n")

        out.append(f"global MSG_{c}: [u8; {len(msg)}] = {arr(msg)};\n")

        out.append(f"global SIG_{c}: [u8; 3293] = {arr(bytes.fromhex(v['sig']))};\n")

        for region, index in (("ctilde", 5), ("z", 1700), ("hint", HINT_START + 3)):
            body = f"    let mut sig = SIG_{c};\n\n    sig[{index}] = sig[{index}] ^ 1;\n\n    assert(!dilithium3_r3::verify(PK_{c}, MSG_{c}, sig));"

            out.append(test_fn(constrained, f"kat_{c}_bad_{region}", body))

            count += 1

        body = f"    let mut msg = MSG_{c};\n\n    msg[0] = msg[0] ^ 1;\n\n    assert(!dilithium3_r3::verify(PK_{c}, msg, SIG_{c}));"

        out.append(test_fn(constrained, f"kat_{c}_bad_msg", body))

        count += 1

    write_package("tampered_r3", "\n".join(out))

    return count


def malformed(constrained, kat):
    """End-to-end rejection of each malformed encoding of KAT vector 0, without a panic."""
    v = kat["vectors"][0]

    sig = bytes.fromhex(v["sig"])

    msg = bytes.fromhex(v["msg"])

    h = sig[HINT_START:]

    offsets = list(h[55:])

    out = ["// Each test breaks one encoding rule of KAT vector 0 (pq-crystals v3.1); verify must return false, not fail.\nuse dilithium::dilithium3_r3;\n"]

    out.append(f"global PK: [u8; 1952] = {arr(bytes.fromhex(v['pk']))};\n")

    out.append(f"global MSG: [u8; {len(msg)}] = {arr(msg)};\n")

    out.append(f"global SIG: [u8; 3293] = {arr(sig)};\n")

    cases = []

    poly = next(i for i in range(6) if (offsets[i] - (offsets[i - 1] if i else 0)) >= 2)

    first = offsets[poly - 1] if poly else 0

    # Two positions of one polynomial swapped, so they are not strictly increasing.
    cases.append(("hint_positions_unordered", [(HINT_START + first, h[first + 1]), (HINT_START + first + 1, h[first])]))

    # A repeated position.
    cases.append(("hint_position_repeated", [(HINT_START + first + 1, h[first])]))

    # Decreasing cumulative counts: the first polynomial's count above the second's.
    cases.append(("hint_counts_decreasing", [(HINT_START + 55, offsets[1] + 1)]))

    # Total count above omega.
    cases.append(("hint_count_above_omega", [(HINT_START + 60, 56)]))

    # A count far above omega in the first polynomial.
    cases.append(("hint_count_255", [(HINT_START + 55, 255)]))

    # Nonzero byte in the unused position area.
    if offsets[5] < 55:
        cases.append(("hint_padding_nonzero", [(HINT_START + 54, 1)]))

    # z coefficient 0 packed as gamma1 - beta and as -(gamma1 - beta): v = 196 and v = 1048380.
    cases.append(("z_norm_low", [(32, 196 & 0xFF), (33, 196 >> 8), (34, (sig[34] & 0xF0) | 0)]))

    cases.append(("z_norm_high", [(32, 1048380 & 0xFF), (33, (1048380 >> 8) & 0xFF), (34, (sig[34] & 0xF0) | (1048380 >> 16))]))

    # z coefficient 1 at the largest packed value.
    cases.append(("z_norm_max", [(34, (sig[34] & 0x0F) | 0xF0), (35, 0xFF), (36, 0xFF)]))

    # c_tilde mismatch.
    cases.append(("c_tilde_mismatch", [(0, sig[0] ^ 0x80)]))

    for name, edits in cases:
        lines = ["    let mut sig = SIG;"]

        for index, value in edits:
            lines.append(f"    sig[{index}] = {value};")

        lines.append("    assert(!dilithium3_r3::verify(PK, MSG, sig));")

        out.append(test_fn(constrained, name, "\n\n".join(lines)))

    out.append(test_fn(constrained, "unmodified_signature_verifies", "    assert(dilithium3_r3::verify(PK, MSG, SIG));"))

    write_package("malformed", "\n".join(out))

    return len(cases) + 1


def prepared(constrained, kat):
    """prepare_key against dilithium-py's tr, A_hat and NTT(t1 * 2^13), and verify_prepared against verify."""
    pre = json.load(open(os.path.join(ROOT, "testdata", "prepared_keys.json")))

    out = ["// prepare_key is checked against tr, A_hat and NTT(t1 * 2^13) computed by dilithium-py 1.5.1;\n// verify_prepared must agree with verify, and the key commitment must not depend on how the key was obtained.\nuse dilithium::{dilithium3_r3, ml_dsa_65, PreparedKey};\n"]

    count = 0

    for i, entry in enumerate(pre["keys"]):
        out.append(f"global PK_{i}: [u8; 1952] = {arr(bytes.fromhex(entry['pk']))};\n")

        out.append(f"global TR32_{i}: [u8; 32] = {arr(bytes.fromhex(entry['tr32']))};\n")

        out.append(f"global TR64_{i}: [u8; 64] = {arr(bytes.fromhex(entry['tr64']))};\n")

        a = "[" + ", ".join("[" + ", ".join(arr(p) for p in row) + "]" for row in entry["a_hat"]) + "]"

        t = "[" + ", ".join(arr(p) for p in entry["t1_hat"]) + "]"

        out.append(f"global A_HAT_{i}: [[[Field; 256]; 5]; 6] = {a};\n")

        out.append(f"global T1_HAT_{i}: [[Field; 256]; 6] = {t};\n")

        body = f"""    let key = dilithium3_r3::prepare_key(PK_{i});

    assert(key.tr == TR32_{i});

    assert(key.a_hat == A_HAT_{i});

    assert(key.t1_hat == T1_HAT_{i});

    let external = PreparedKey {{ tr: TR32_{i}, a_hat: A_HAT_{i}, t1_hat: T1_HAT_{i} }};

    assert(dilithium3_r3::key_commitment(key) == dilithium3_r3::key_commitment(external));"""

        out.append(test_fn(constrained, f"prepare_key_r3_{i}", body))

        body = f"""    let key = ml_dsa_65::prepare_key(PK_{i});

    assert(key.tr == TR64_{i});

    assert(key.a_hat == A_HAT_{i});

    assert(key.t1_hat == T1_HAT_{i});

    let r3 = dilithium3_r3::prepare_key(PK_{i});

    assert(ml_dsa_65::key_commitment(key) != dilithium3_r3::key_commitment(r3));"""

        out.append(test_fn(constrained, f"prepare_key_mldsa65_{i}", body))

        count += 2

    for v in kat["vectors"]:
        idx = next((i for i, e in enumerate(pre["keys"]) if e["pk"] == v["pk"]), None)

        if idx is None:
            continue

        c = v["count"]

        msg = bytes.fromhex(v["msg"])

        out.append(f"global MSG_{c}: [u8; {len(msg)}] = {arr(msg)};\n")

        out.append(f"global SIG_{c}: [u8; 3293] = {arr(bytes.fromhex(v['sig']))};\n")

        body = f"""    let key = PreparedKey {{ tr: TR32_{idx}, a_hat: A_HAT_{idx}, t1_hat: T1_HAT_{idx} }};

    assert(dilithium3_r3::verify_prepared(key, MSG_{c}, SIG_{c}) == dilithium3_r3::verify(PK_{idx}, MSG_{c}, SIG_{c}));

    assert(dilithium3_r3::verify_prepared(key, MSG_{c}, SIG_{c}));

    let mut bad = SIG_{c};

    bad[1700] = bad[1700] ^ 1;

    assert(dilithium3_r3::verify_prepared(key, MSG_{c}, bad) == dilithium3_r3::verify(PK_{idx}, MSG_{c}, bad));"""

        out.append(test_fn(constrained, f"prepared_equals_full_kat_{c}", body))

        count += 1

    write_package("prepared", "\n".join(out))

    return count


def edge(constrained):
    """Valid signatures that reach encoding edge cases (testdata/edge_vectors.json): verify must accept them."""
    data = json.load(open(os.path.join(ROOT, "testdata", "edge_vectors.json")))

    out = [f"// {data['meta']['source']}.\nuse dilithium::{{dilithium3_r3, ml_dsa_65}};\n"]

    for v in data["vectors"]:
        n = v["name"].upper()

        msg = bytes.fromhex(v["msg"])

        sig = bytes.fromhex(v["sig"])

        out.append(f"global PK_{n}: [u8; 1952] = {arr(bytes.fromhex(v['pk']))};\n")

        out.append(f"global MSG_{n}: [u8; {len(msg)}] = {arr(msg)};\n")

        out.append(f"global SIG_{n}: [u8; {len(sig)}] = {arr(sig)};\n")

        if v["mode"] == "ml_dsa_65":
            ctx = bytes.fromhex(v["ctx"])

            out.append(f"global CTX_{n}: [u8; {len(ctx)}] = {arr(ctx)};\n")

            call = f"ml_dsa_65::verify(PK_{n}, MSG_{n}, CTX_{n}, SIG_{n})"
        else:
            call = f"dilithium3_r3::verify(PK_{n}, MSG_{n}, SIG_{n})"

        out.append(test_fn(constrained, v["name"], f"    assert({call});"))

    write_package("edge", "\n".join(out))

    return len(data["vectors"])


def main():
    global OUT

    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if len(args) != 1:
        sys.exit(__doc__)

    OUT = os.path.abspath(args[0])

    if OUT == ROOT or OUT.startswith(ROOT + os.sep):
        sys.exit("OUT_DIR must be outside the repository")

    constrained = "--constrained" in sys.argv

    kat = json.load(open(os.path.join(ROOT, "testdata", "kat_dilithium3_r3.json")))

    n_kat = kat_r3(constrained)

    n_acvp = acvp(constrained)

    n_tampered = tampered_r3(constrained, kat)

    n_bad = malformed(constrained, kat)

    n_pre = prepared(constrained, kat)

    n_edge = edge(constrained)

    mode = "constrained" if constrained else "unconstrained"

    print(f"generated {mode} tests: kat_r3 {n_kat}, acvp_mldsa65 {n_acvp}, tampered_r3 {n_tampered}, malformed {n_bad}, prepared {n_pre}, edge {n_edge}")


if __name__ == "__main__":
    main()
