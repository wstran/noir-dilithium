use crate::keccak::{absorb_bytes, lanes_to_bytes, SHAKE256_RATE, squeeze};
use crate::ntt::ntt;
use crate::packing::decode_t1;
use crate::sample::expand_a;

// Public-key material in the form the verifier consumes: tr = H(pk), A_hat = ExpandA(rho) and
// t1_hat = NTT(t1 * 2^13).
pub struct PreparedKey<let TR: u32> {
    pub tr: [u8; TR],
    pub a_hat: [[[Field; 256]; 5]; 6],
    pub t1_hat: [[Field; 256]; 6],
}

pub(crate) fn prepare<let TR: u32>(pk: [u8; 1952]) -> PreparedKey<TR> {
    let mut rho: [u8; 32] = [0; 32];

    for i in 0..32 {
        rho[i] = pk[i];
    }

    let a_hat = expand_a(rho);

    let t1 = decode_t1(pk);

    let mut t1_hat: [[Field; 256]; 6] = [[0; 256]; 6];

    for i in 0..6 {
        let mut scaled: [Field; 256] = [0; 256];

        for x in 0..256 {
            scaled[x] = t1[i][x] * 8192;
        }

        t1_hat[i] = ntt(scaled);
    }

    let tr_lanes: [u64; TR / 8] =
        squeeze::<SHAKE256_RATE, TR / 8>(absorb_bytes::<SHAKE256_RATE, 1952>(pk));

    PreparedKey { tr: lanes_to_bytes(tr_lanes), a_hat, t1_hat }
}

// Poseidon2 sponge (rate 3) over tr packed in 16-byte little-endian chunks followed by the 9216 coefficients in the
// order A_hat[i][0..5], t1_hat[i] for i = 0..6, packed 10 per field element (23 bits each, little-endian). The
// capacity element starts at mode * 2^64 + (number of field elements). Coefficients must be below q (asserted), so
// every prepared key has exactly one commitment.
pub(crate) fn commitment<let TR: u32>(key: PreparedKey<TR>, mode: Field) -> Field {
    let mut packed: [Field; TR / 16 + 922] = [0; TR / 16 + 922];

    for c in 0..TR / 16 {
        let mut v: Field = 0;

        let mut scale: Field = 1;

        for i in 0..16 {
            v = v + (key.tr[c * 16 + i] as Field) * scale;

            scale = scale * 256;
        }

        packed[c] = v;
    }

    let mut n: u32 = 0;

    for i in 0..6 {
        for j in 0..6 {
            for x in 0..256 {
                let coeff = if j < 5 {
                    key.a_hat[i][j][x]
                } else {
                    key.t1_hat[i][x]
                };

                coeff.assert_max_bit_size::<23>();

                (8380416 - coeff).assert_max_bit_size::<23>();

                let slot = TR / 16 + n / 10;

                let mut weight: Field = 1;

                for _ in 0..(n % 10) {
                    weight = weight * 8388608;
                }

                packed[slot] = packed[slot] + coeff * weight;

                n += 1;
            }
        }
    }

    let total = TR / 16 + 922;

    let mut state: [Field; 4] = [0, 0, 0, mode * 18446744073709551616 + total as Field];

    for chunk in 0..(total + 2) / 3 {
        for k in 0..3 {
            let idx = 3 * chunk + k;

            if idx < total {
                state[k] = state[k] + packed[idx];
            }
        }

        state = std::hash::poseidon2_permutation(state);
    }

    state[0]
}
