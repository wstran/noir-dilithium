// ML-DSA-65 as specified in FIPS 204 (August 2024): tr = H(pk, 64), mu = H(tr || M', 64), c_tilde of 48 bytes,
// signatures of 3309 bytes. Only the pure variant is provided (no HashML-DSA).
use crate::core::verify_with_mu;
use crate::keccak::{bytes_to_lanes, concat, shake256_bytes};
use crate::key::{commitment, prepare, PreparedKey};

pub global PK_BYTES: u32 = 1952;

pub global SIG_BYTES: u32 = 3309;

pub global TR_BYTES: u32 = 64;

global MODE: Field = 2;

// Derives the verifier form of pk inside the circuit (ExpandA, tr and NTT(t1 * 2^13)).
pub fn prepare_key(pk: [u8; 1952]) -> PreparedKey<64> {
    prepare(pk)
}

// Binding commitment to a prepared key, domain-separated from Dilithium3 round 3.
pub fn key_commitment(key: PreparedKey<64>) -> Field {
    commitment(key, MODE)
}

// ML-DSA.Verify_internal with mu = H(tr || M', 64) supplied by the caller (FIPS 204 external mu). Like every
// *_prepared function it trusts key: the caller must bind key to the signer, for example by checking
// key_commitment(key) against a value derived with prepare_key from the real public key. The caller is also
// responsible for binding mu to the intended message.
pub fn verify_mu_prepared(key: PreparedKey<64>, mu: [u8; 64], sig: [u8; 3309]) -> bool {
    verify_with_mu::<48, 3309>(key.a_hat, key.t1_hat, bytes_to_lanes(mu, 0), sig)
}

// ML-DSA.Verify_internal (FIPS 204 Algorithm 8) on the formatted message M'. Trusts key, see verify_mu_prepared.
pub fn verify_internal_prepared<let N: u32>(
    key: PreparedKey<64>,
    m_prime: [u8; N],
    sig: [u8; 3309],
) -> bool {
    let mu: [u64; 8] = shake256_bytes(concat(key.tr, m_prime));

    verify_with_mu::<48, 3309>(key.a_hat, key.t1_hat, mu, sig)
}

// ML-DSA.Verify (FIPS 204 Algorithm 3): M' = 0 || |ctx| || ctx || M. Returns false if ctx exceeds 255 bytes.
// Trusts key, see verify_mu_prepared.
pub fn verify_prepared<let N: u32, let C: u32>(
    key: PreparedKey<64>,
    msg: [u8; N],
    ctx: [u8; C],
    sig: [u8; 3309],
) -> bool {
    if C > 255 {
        false
    } else {
        let prefix: [u8; 2] = [0, C as u8];

        verify_internal_prepared(key, concat(concat(prefix, ctx), msg), sig)
    }
}

// The same three entry points from the raw public key.
pub fn verify_mu(pk: [u8; 1952], mu: [u8; 64], sig: [u8; 3309]) -> bool {
    verify_mu_prepared(prepare_key(pk), mu, sig)
}

pub fn verify_internal<let N: u32>(pk: [u8; 1952], m_prime: [u8; N], sig: [u8; 3309]) -> bool {
    verify_internal_prepared(prepare_key(pk), m_prime, sig)
}

pub fn verify<let N: u32, let C: u32>(
    pk: [u8; 1952],
    msg: [u8; N],
    ctx: [u8; C],
    sig: [u8; 3309],
) -> bool {
    verify_prepared(prepare_key(pk), msg, ctx, sig)
}
