// The cheap path for ML-DSA-65: a 32-byte message with an empty context under a prepared key.
use dilithium::{ml_dsa_65, PreparedKey};

fn main(
    tr: [u8; 64],
    a_hat: [[[Field; 256]; 5]; 6],
    t1_hat: [[Field; 256]; 6],
    msg: [u8; 32],
    sig: [u8; 3309],
) -> pub Field {
    let key = PreparedKey { tr, a_hat, t1_hat };

    let ctx: [u8; 0] = [];

    assert(ml_dsa_65::verify_prepared(key, msg, ctx, sig));

    ml_dsa_65::key_commitment(key)
}
