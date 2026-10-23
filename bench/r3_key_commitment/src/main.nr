// The key commitment alone, to separate its cost from verification.
use dilithium::{dilithium3_r3, PreparedKey};

fn main(tr: [u8; 32], a_hat: [[[Field; 256]; 5]; 6], t1_hat: [[Field; 256]; 6]) -> pub Field {
    dilithium3_r3::key_commitment(PreparedKey { tr, a_hat, t1_hat })
}
