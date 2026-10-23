// Key preparation for ML-DSA-65.
use dilithium::ml_dsa_65;

fn main(pk: [u8; 1952]) -> pub Field {
    ml_dsa_65::key_commitment(ml_dsa_65::prepare_key(pk))
}
