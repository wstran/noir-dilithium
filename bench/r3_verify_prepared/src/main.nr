// The cheap path: one Dilithium3 (round 3) signature on a 32-byte message under a prepared key, exposing the
// key commitment so the proof binds to a key prepared elsewhere.
use dilithium::{dilithium3_r3, PreparedKey};

fn main(
    tr: [u8; 32],
    a_hat: [[[Field; 256]; 5]; 6],
    t1_hat: [[Field; 256]; 6],
    msg: [u8; 32],
    sig: [u8; 3293],
) -> pub Field {
    let key = PreparedKey { tr, a_hat, t1_hat };

    assert(dilithium3_r3::verify_prepared(key, msg, sig));

    dilithium3_r3::key_commitment(key)
}
