use crate::hint::use_hint;
use crate::keccak::{bytes_to_lanes, shake256_lanes};
use crate::ntt::{inv_ntt, ntt, reduce};
use crate::packing::{decode_hint, decode_z};
use crate::params::Q;
use crate::sample::sample_in_ball;

// Verification after mu = H(tr || M', 64) is known, for a c_tilde of CT bytes and a signature of SIG bytes.
pub(crate) fn verify_with_mu<let CT: u32, let SIG: u32>(
    a_hat: [[[Field; 256]; 5]; 6],
    t1_hat: [[Field; 256]; 6],
    mu: [u64; 8],
    sig: [u8; SIG],
) -> bool {
    let c_tilde: [u64; CT / 8] = bytes_to_lanes(sig, 0);

    let (z, z_ok) = decode_z(sig, CT);

    let (h, h_ok) = decode_hint(sig);

    let (c, c_ok) = sample_in_ball(c_tilde);

    let c_hat = ntt(c);

    let mut z_hat: [[Field; 256]; 5] = [[0; 256]; 5];

    for j in 0..5 {
        z_hat[j] = ntt(z[j]);
    }

    let mut final_input: [u64; 104] = [0; 104];

    for i in 0..8 {
        final_input[i] = mu[i];
    }

    for i in 0..6 {
        let mut w_hat: [Field; 256] = [0; 256];

        for x in 0..256 {
            // q * 2^24 keeps the sum positive: c_hat * t1_hat < q^2 < q * 2^24.
            let mut s: Field = Q * 16777216 - c_hat[x] * t1_hat[i][x];

            for j in 0..5 {
                s = s + a_hat[i][j][x] * z_hat[j][x];
            }

            w_hat[x] = reduce(s);
        }

        let w = inv_ntt(w_hat);

        for lane in 0..16 {
            let mut v: Field = 0;

            let mut scale: Field = 1;

            for n in 0..16 {
                let x = lane * 16 + n;

                v = v + use_hint(h[i * 256 + x], w[x]) * scale;

                scale = scale * 16;
            }

            final_input[8 + i * 16 + lane] = v as u64;
        }
    }

    let c_check: [u64; CT / 8] = shake256_lanes(final_input);

    let mut hash_ok = true;

    for i in 0..CT / 8 {
        hash_ok = hash_ok & (c_check[i] == c_tilde[i]);
    }

    z_ok & h_ok & c_ok & hash_ok
}
