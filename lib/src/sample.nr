use crate::keccak::{absorb_bytes, lanes_to_bytes, SHAKE128_RATE, shake256_lanes, squeeze};
use crate::params::Q;

// SampleInBall: the challenge polynomial with TAU = 49 coefficients equal to +-1 (stored as 1 or q - 1).
// The second return value is false only if 272 bytes of SHAKE256 output do not yield 49 positions, which
// happens with probability below 2^-350; the reference would keep squeezing.
pub(crate) fn sample_in_ball<let CTL: u32>(c_tilde: [u64; CTL]) -> ([Field; 256], bool) {
    let stream_lanes: [u64; 34] = shake256_lanes(c_tilde);

    let stream: [u8; 272] = lanes_to_bytes(stream_lanes);

    let signs: [bool; 64] = (stream_lanes[0] as Field).to_le_bits();

    let mut c: [Field; 256] = [0; 256];

    let mut count: u32 = 0;

    for t in 8..272 {
        let active = count < 49;

        let slot = if active { count } else { 48 };

        let i = 207 + slot;

        let b = stream[t] as u32;

        if active & (b <= i) {
            let sign = if signs[slot] { Q - 1 } else { 1 };

            c[i] = c[b];

            c[b] = sign;

            count += 1;
        }
    }

    (c, count == 49)
}

unconstrained fn first_accepted(accepted: [bool; 280]) -> [u32; 256] {
    let mut sel: [u32; 256] = [0; 256];

    let mut n: u32 = 0;

    for t in 0..280 {
        if accepted[t] & (n < 256) {
            sel[n] = t;

            n += 1;
        }
    }

    sel
}

// RejNTTPoly(rho || j || i): coefficients are the first 256 three-byte candidates below q, read from five
// SHAKE128 blocks (280 candidates). Fewer than 256 accepted candidates (probability below 2^-120 per
// polynomial) makes the circuit unsatisfiable instead of squeezing more.
pub(crate) fn rej_ntt_poly(rho: [u8; 32], i: u8, j: u8) -> [Field; 256] {
    let mut seed: [u8; 34] = [0; 34];

    for t in 0..32 {
        seed[t] = rho[t];
    }

    seed[32] = j;

    seed[33] = i;

    let lanes: [u64; 105] = squeeze::<SHAKE128_RATE, 105>(absorb_bytes::<SHAKE128_RATE, 34>(seed));

    let bytes: [u8; 840] = lanes_to_bytes(lanes);

    let mut cand: [Field; 280] = [0; 280];

    let mut accepted: [bool; 280] = [false; 280];

    // key[t] equals the number of accepted candidates before t when t is accepted, and is at least 280 otherwise.
    let mut key: [Field; 280] = [0; 280];

    let mut prefix: Field = 0;

    for t in 0..280 {
        let v = (bytes[3 * t] as Field)
            + (bytes[3 * t + 1] as Field) * 256
            + ((bytes[3 * t + 2] & 0x7F) as Field) * 65536;

        let ok = (v as u32) < 8380417;

        cand[t] = v;

        accepted[t] = ok;

        key[t] = if ok { prefix } else { 1000 };

        prefix = prefix + (ok as Field);

        // Without a fresh witness each key[t] would carry the whole running sum as a linear expression.
        std::as_witness(prefix);
    }

    // Safety: for every output i, key[sel[i]] == i forces candidate sel[i] to be accepted with exactly i
    // accepted candidates before it, so sel[i] is the index of the (i + 1)-th accepted candidate.
    let sel = unsafe { first_accepted(accepted) };

    let mut out: [Field; 256] = [0; 256];

    for i in 0..256 {
        let s = sel[i];

        assert(key[s] == i as Field);

        out[i] = cand[s];
    }

    out
}

// ExpandA: A_hat[i][j] = RejNTTPoly(rho || j || i), already in the NTT domain.
pub(crate) fn expand_a(rho: [u8; 32]) -> [[[Field; 256]; 5]; 6] {
    let mut a_hat: [[[Field; 256]; 5]; 6] = [[[0; 256]; 5]; 6];

    for i in 0..6 {
        for j in 0..5 {
            a_hat[i][j] = rej_ntt_poly(rho, i as u8, j as u8);
        }
    }

    a_hat
}
