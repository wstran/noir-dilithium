// One ML-DSA-65 signature on a 32-byte message with an empty context under the raw public key.
use dilithium::ml_dsa_65;

fn main(pk: [u8; 1952], msg: [u8; 32], sig: [u8; 3309]) {
    let ctx: [u8; 0] = [];

    assert(ml_dsa_65::verify(pk, msg, ctx, sig));
}
