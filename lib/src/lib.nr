// In-circuit verification of CRYSTALS-Dilithium signatures in two modes that share one core:
// Dilithium3 as specified in round 3 (v3.1) and ML-DSA-65 as specified in FIPS 204.
mod params;
mod ntt;
mod keccak;
mod sample;
mod packing;
mod hint;
mod hint_cases;
mod core;
mod key;

pub mod dilithium3_r3;
pub mod ml_dsa_65;

pub use key::PreparedKey;
