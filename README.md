# noir-dilithium

Verification of CRYSTALS-Dilithium signatures inside [Noir](https://noir-lang.org) circuits, in two modes that
share one core:

- **ML-DSA-65**, as standardized in FIPS 204 (August 2024). Tested against the NIST ACVP sigVer vectors.
- **Dilithium3 round 3**, as specified in version 3.1 of the submission (February 2021), the variant used by
  systems deployed before FIPS 204. Tested against the known-answer tests of the pq-crystals reference
  implementation.

> **Status: experimental and not audited.** Do not rely on it to protect real assets before an independent
> review. Bugs in a circuit library can let invalid proofs be accepted.

## Modes

Both modes use the same parameters (q = 8380417, k = 6, l = 5, tau = 49, gamma1 = 2^19,
gamma2 = (q - 1) / 32, beta = 196, omega = 55) and the same public key format (1952 bytes).

| | ML-DSA-65 | Dilithium3 round 3 |
|---|---|---|
| module | `ml_dsa_65` | `dilithium3_r3` |
| tr | H(pk, 64) | H(pk, 32) |
| mu | H(tr \|\| M', 64), M' = 0 \|\| len(ctx) \|\| ctx \|\| M | H(tr \|\| M, 64) |
| c_tilde | 48 bytes (the whole value seeds SampleInBall) | 32 bytes |
| signature | 3309 bytes | 3293 bytes |

H is SHAKE256. HashML-DSA (the pre-hash variant of FIPS 204) is not provided.

## Installation

```toml
[dependencies]
dilithium = { git = "https://github.com/wstran/noir-dilithium", tag = "v0.1.0", directory = "lib" }
```

Built and tested with Noir 1.0.0-rc.6 and Barretenberg (bb) 6.0.0.

## Example

```noir
use dilithium::ml_dsa_65;

fn main(pk: pub [u8; 1952], msg: pub [u8; 32], sig: [u8; 3309]) {
    let ctx: [u8; 0] = [];

    assert(ml_dsa_65::verify(pk, msg, ctx, sig));
}
```

## API

Message and context lengths are compile-time array lengths. Every function returns `false` for any signature the
specification rejects; a malformed signature never makes the circuit unsatisfiable, so a circuit can count valid
signatures instead of asserting each one.

```noir
use dilithium::{dilithium3_r3, ml_dsa_65, PreparedKey};

// ML-DSA-65
ml_dsa_65::verify(pk: [u8; 1952], msg: [u8; N], ctx: [u8; C], sig: [u8; 3309]) -> bool   // false if C > 255
ml_dsa_65::verify_internal(pk: [u8; 1952], m_prime: [u8; N], sig: [u8; 3309]) -> bool    // Verify_internal on M'
ml_dsa_65::verify_mu(pk: [u8; 1952], mu: [u8; 64], sig: [u8; 3309]) -> bool              // external mu
ml_dsa_65::prepare_key(pk: [u8; 1952]) -> PreparedKey<64>
ml_dsa_65::key_commitment(key: PreparedKey<64>) -> Field
ml_dsa_65::verify_prepared(key, msg, ctx, sig) -> bool
ml_dsa_65::verify_internal_prepared(key, m_prime, sig) -> bool
ml_dsa_65::verify_mu_prepared(key, mu, sig) -> bool

// Dilithium3 round 3
dilithium3_r3::verify(pk: [u8; 1952], msg: [u8; N], sig: [u8; 3293]) -> bool
dilithium3_r3::prepare_key(pk: [u8; 1952]) -> PreparedKey<32>
dilithium3_r3::key_commitment(key: PreparedKey<32>) -> Field
dilithium3_r3::verify_prepared(key: PreparedKey<32>, msg: [u8; N], sig: [u8; 3293]) -> bool
```

`PreparedKey<TR>` holds `tr`, `a_hat = ExpandA(rho)` (6 x 5 polynomials, NTT domain) and
`t1_hat = NTT(t1 * 2^13)` (6 polynomials). `verify(pk, ...)` is exactly `verify_prepared(prepare_key(pk), ...)`.
`verify_mu` and `verify_internal` accept whatever mu or M' they are given; binding it to the intended message is
the caller's job.

### Prepared keys

`verify` derives the key inside the circuit, which costs about 3.4 million gates (mostly the 150 SHAKE128 blocks of
ExpandA). When one signer is verified many times, prepare the key once in a separate proof and verify against it:

```noir
use dilithium::{dilithium3_r3, PreparedKey};

// Registration proof, once per key. The public key is a public input, so whoever checks this proof sees which
// key the published commitment belongs to.
fn register(pk: pub [u8; 1952]) -> pub Field {
    dilithium3_r3::key_commitment(dilithium3_r3::prepare_key(pk))
}

// Every later proof. The commitment and the message are public inputs; the verifier accepts the proof only if
// `registered` is a commitment it has already accepted from a registration proof of the expected signer.
fn check(key: PreparedKey<32>, registered: pub Field, msg: pub [u8; 32], sig: [u8; 3293]) {
    assert(dilithium3_r3::key_commitment(key) == registered);

    assert(dilithium3_r3::verify_prepared(key, msg, sig));
}
```

**`verify_prepared` trusts its key.** A circuit that calls it must bind the key to the real signer, and the
statement must bind the message, as `register` and `check` do through their public inputs; otherwise anyone can
verify a signature of their own against a key of their choice. An application that does not want 1952 public bytes
can expose a hash of the public key computed inside the registration circuit instead.

The commitment is a Poseidon2 sponge (BN254, width 4, rate 3, `std::hash::poseidon2_permutation`) over `tr` in
16-byte little-endian chunks, then the 9216 coefficients of A_hat and t1_hat in the order
`for i in 0..6 { A_hat[i][0..5], t1_hat[i] }`, ten coefficients per field element at weight 2^(23 * (n mod 10)).
The capacity element starts at `mode * 2^64 + count`, with mode 1 for Dilithium3 round 3, mode 2 for ML-DSA-65,
and count the number of field elements (924 and 926). Absorbed chunks are zero padded. `key_commitment` asserts
that every coefficient is below q, so each prepared key has exactly one commitment.

## Rejection rules

`verify` returns `false` exactly when the specification does (except for the bounded SampleInBall loop described
below), including:

- hint encoding: per-polynomial counts that decrease or exceed omega, positions that are not strictly increasing
  within a polynomial, nonzero unused position bytes;
- ||z||inf >= gamma1 - beta;
- c_tilde different from H(mu || w1Encode(w1'));
- ML-DSA-65 with a context longer than 255 bytes.

Two bounded loops replace the open-ended ones of the specification:

- SampleInBall reads at most 272 bytes of SHAKE256 output. Needing more has probability below 2^-350 for a random
  c_tilde; such a signature is reported invalid.
- ExpandA reads five SHAKE128 blocks (280 candidates) per polynomial. A public key whose rho needs more has
  probability below 2^-120; preparing such a key makes the circuit unsatisfiable.

All unconstrained helpers are checked in-circuit: the mod q reduction (quotient and remainder range-checked,
recombination asserted), Decompose inside UseHint (unique decomposition asserted), and the choice of accepted
ExpandA candidates (each chosen candidate must be accepted with the right number of accepted candidates before
it).

## Cost

Measured with Noir 1.0.0-rc.6 and bb 6.0.0 (UltraHonk, `-t noir-recursive-no-zk`). Gate counts are from `bb gates`
on the circuits in `bench/`, each verifying one signature on a 32-byte message.

| circuit | gates |
|---|---|
| `ml_dsa_65::verify_prepared` (empty context) + `key_commitment` | 577,843 |
| `ml_dsa_65::verify` (empty context) | 3,869,436 |
| `ml_dsa_65::prepare_key` + `key_commitment` | 3,415,697 |
| `dilithium3_r3::verify_prepared` + `key_commitment` | 577,419 |
| `dilithium3_r3::verify` | 3,869,080 |
| `dilithium3_r3::prepare_key` + `key_commitment` | 3,415,560 |
| `key_commitment` alone | 65,978 |

Proving one signature (medians of 3 runs; Apple M3 Pro, Linux VM with 6 vCPU and 16 GB, container limited to 6
CPUs, no other jobs running; witness time is `nargo execute` including program loading; bb's reference string is
cached between runs; peak memory is the largest of the runs):

| circuit | witness | prove wall | prove CPU | prove peak memory | proof |
|---|---|---|---|---|---|
| `ml_dsa_65::verify_prepared` (empty context) + `key_commitment` | 0.94 s | 2.45 s | 9.6 s | 1.0 GiB | 13,120 bytes |
| `ml_dsa_65::verify` (empty context) | 1.87 s | 19.4 s | 73.6 s | 5.4 GiB | 13,120 bytes |
| `dilithium3_r3::verify_prepared` + `key_commitment` | 0.94 s | 2.46 s | 9.6 s | 1.0 GiB | 13,120 bytes |
| `dilithium3_r3::verify` | 1.67 s | 17.8 s | 68.3 s | 5.4 GiB | 13,120 bytes |

Every proof verified with `bb verify`. The `noir-recursive-no-zk` target does not hide private inputs; prove with a
zero-knowledge target if the signature or the key must stay private.

`scripts/bench_docker.sh` reproduces these numbers (`RUNS`, `MEMORY` and `CPUS` are adjustable). It keeps bb's
reference string in `BB_CRS_DIR` (default `bench/out/bb-crs`); without that cache every run downloads and unpacks
it again, which adds several seconds of wall and CPU time to each proof. The bench inputs are made by
`scripts/make_bench_inputs.py` from deterministic dilithium-py keys.

## Tests

```sh
scripts/test.sh                  # unit tests and every vector suite (unconstrained)
CONSTRAINED=1 scripts/test.sh    # the vector suites as constrained tests (ACIR witness generation, slow)
SUITES="edge malformed" scripts/test.sh
```

`scripts/test.sh` needs `nargo` and `python3` on `PATH`. The vector suites are generated from `testdata/` by
`scripts/gen_tests.py` into a temporary directory. `testdata/README.md` gives the source and license notice of
each vector file.

| suite | tests | source |
|---|---|---|
| unit (`lib`) | 9 | SHAKE128 and SHAKE256 known answers; UseHint on 98 boundary values and 500 seeded random values for both hint bits against a Python transcription of FIPS 204 (constrained and unconstrained); hint and z decoder rules |
| `kat_r3` | 100 | pq-crystals reference KATs for Dilithium3 at tag v3.1 (`PQCsignKAT_Dilithium3.rsp`, sha256 `8196b32212753f525346201ffec1c7a0a852596fa0b57bd4e2746231dab44d55`, rebuilt by `scripts/build_kat_r3.sh`) |
| `acvp_mldsa65` | 46 | NIST ACVP-Server ML-DSA-sigVer-FIPS204 `internalProjection.json` (sha256 `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437`, commit `a7f283cd`): the 45 ML-DSA-65 cases of the pure, internal and external-mu groups, 9 valid and 36 invalid, plus a context of 256 bytes |
| `tampered_r3` | 120 | the first 30 KAT vectors, each with one byte of c_tilde, z, the hint encoding or the message flipped |
| `malformed` | 11 | one broken encoding rule per test on KAT vector 0, plus the unmodified signature |
| `prepared` | 18 | `prepare_key` output equal to tr, A_hat and NTT(t1 * 2^13) from dilithium-py 1.5.1 for six KAT keys in both modes, the commitments, and `verify_prepared` equal to `verify` |
| `edge` | 6 | valid signatures generated with dilithium-py: ML-DSA-65 with an empty and with a 255-byte context, a hint polynomial with no hints and the largest number of hints (55), in both modes |

All 310 tests pass both unconstrained and constrained with Noir 1.0.0-rc.6 (the constrained run took about 19 minutes
on 6 CPUs). Every vector was also checked with dilithium-py 1.5.1 when `testdata/` was built.

`scripts/check/use_hint.sh` replays the circuit's UseHint, including each in-circuit assertion, for all
2 x 8380417 pairs (r, h) with r < q and compares it with the pq-crystals reference `use_hint` (v3.1,
`ref/rounding.c`) and with FIPS 204 Algorithms 36 and 40: no mismatch and no unsatisfiable assertion. With
`OLD_RULE=1` it replays the sign test of an earlier draft (`(u - 1) as u32 > 261887` in the r - r0 = q - 1 case)
and reports the one wrong output, r = 8118529 with h = 1.

## Limitations

- Not audited.
- HashML-DSA (pre-hash) is not provided.
- The edge-case vectors are generated with dilithium-py, not taken from an official source.
- CI runs every vector suite unconstrained and the malformed, prepared-key and edge suites constrained; the full
  constrained run (`CONSTRAINED=1 scripts/test.sh`, about 19 minutes on 6 CPUs) is run by hand.

## Layout

```
lib/        the library (Nargo package "dilithium")
bench/      one-signature circuits used for gate counts and timings, with Prover.toml inputs
testdata/   vector files (pq-crystals KAT, NIST ACVP, edge cases, prepared keys) and their sources
scripts/    test and benchmark runners, vector extraction, test generation, the exhaustive UseHint check
```

## Security

Please report vulnerabilities privately through GitHub's "Report a vulnerability" form on this repository rather
than in a public issue.

## License

Licensed under either of the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license
([LICENSE-MIT](LICENSE-MIT)), at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
