// Key preparation for Dilithium3 (round 3): the commitment a cheap-path proof is checked against.
use dilithium::dilithium3_r3;

fn main(pk: [u8; 1952]) -> pub Field {
    dilithium3_r3::key_commitment(dilithium3_r3::prepare_key(pk))
}
