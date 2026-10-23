// One Dilithium3 (round 3) signature on a 32-byte message under the raw public key.
use dilithium::dilithium3_r3;

fn main(pk: [u8; 1952], msg: [u8; 32], sig: [u8; 3293]) {
    assert(dilithium3_r3::verify(pk, msg, sig));
}
