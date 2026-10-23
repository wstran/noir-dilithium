// CRYSTALS-Dilithium3 as specified in round 3 (v3.1, February 2021), the variant used by pre-FIPS 204
// deployments: tr = H(pk, 32), mu = H(tr || M, 64), c_tilde of 32 bytes, signatures of 3293 bytes.
use crate::core::verify_with_mu;
use crate::keccak::{concat, shake256_bytes};
use crate::key::{commitment, prepare, PreparedKey};

pub global PK_BYTES: u32 = 1952;

pub global SIG_BYTES: u32 = 3293;

pub global TR_BYTES: u32 = 32;

global MODE: Field = 1;

// Derives the verifier form of pk inside the circuit (ExpandA, tr and NTT(t1 * 2^13)).
pub fn prepare_key(pk: [u8; 1952]) -> PreparedKey<32> {
    prepare(pk)
}

// Binding commitment to a prepared key, domain-separated from ML-DSA-65.
pub fn key_commitment(key: PreparedKey<32>) -> Field {
    commitment(key, MODE)
}

// Verifies sig on msg under a prepared key. The caller must bind key to the signer, for example by checking
// key_commitment(key) against a value derived with prepare_key from the real public key.
pub fn verify_prepared<let N: u32>(key: PreparedKey<32>, msg: [u8; N], sig: [u8; 3293]) -> bool {
    let mu: [u64; 8] = shake256_bytes(concat(key.tr, msg));

    verify_with_mu::<32, 3293>(key.a_hat, key.t1_hat, mu, sig)
}

// Verifies sig on msg under the raw public key.
pub fn verify<let N: u32>(pk: [u8; 1952], msg: [u8; N], sig: [u8; 3293]) -> bool {
    verify_prepared(prepare_key(pk), msg, sig)
}
