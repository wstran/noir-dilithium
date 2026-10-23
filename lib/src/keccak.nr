// Keccak-f[1600] sponges with the SHAKE domain separator 0x1F. RATE is the rate in 64-bit lanes: 17 for
// SHAKE256, 21 for SHAKE128. Input lengths are compile-time constants, so padding is placed at compile time.
pub(crate) global SHAKE128_RATE: u32 = 21;

pub(crate) global SHAKE256_RATE: u32 = 17;

pub(crate) fn absorb_bytes<let RATE: u32, let N: u32>(input: [u8; N]) -> [u64; 25] {
    let block_bytes = RATE * 8;

    let blocks = N / block_bytes + 1;

    let mut s: [u64; 25] = [0; 25];

    for b in 0..blocks {
        for i in 0..RATE {
            let mut v: Field = 0;

            let mut scale: Field = 1;

            for j in 0..8 {
                let idx = b * block_bytes + i * 8 + j;

                let mut byte: Field = 0;

                if idx < N {
                    byte = input[idx] as Field;
                }

                if idx == N {
                    byte = 0x1F;
                }

                if idx == blocks * block_bytes - 1 {
                    byte = byte + 0x80;
                }

                v = v + byte * scale;

                scale = scale * 256;
            }

            s[i] = s[i] ^ (v as u64);
        }

        s = std::hash::keccakf1600(s);
    }

    s
}

pub(crate) fn absorb_lanes<let RATE: u32, let N: u32>(input: [u64; N]) -> [u64; 25] {
    let blocks = N / RATE + 1;

    let mut s: [u64; 25] = [0; 25];

    for b in 0..blocks {
        for i in 0..RATE {
            let idx = b * RATE + i;

            let mut v: u64 = 0;

            if idx < N {
                v = input[idx];
            }

            if idx == N {
                v = 0x1F;
            }

            if (b == blocks - 1) & (i == RATE - 1) {
                v = v ^ 0x8000000000000000;
            }

            s[i] = s[i] ^ v;
        }

        s = std::hash::keccakf1600(s);
    }

    s
}

pub(crate) fn squeeze<let RATE: u32, let OUT: u32>(state: [u64; 25]) -> [u64; OUT] {
    let mut s = state;

    let mut out: [u64; OUT] = [0; OUT];

    for i in 0..OUT {
        if (i > 0) & (i % RATE == 0) {
            s = std::hash::keccakf1600(s);
        }

        out[i] = s[i % RATE];
    }

    out
}

pub(crate) fn bytes_to_lanes<let NB: u32, let NL: u32>(bytes: [u8; NB], offset: u32) -> [u64; NL] {
    let mut lanes: [u64; NL] = [0; NL];

    for i in 0..NL {
        let mut v: Field = 0;

        let mut scale: Field = 1;

        for j in 0..8 {
            v = v + (bytes[offset + i * 8 + j] as Field) * scale;

            scale = scale * 256;
        }

        lanes[i] = v as u64;
    }

    lanes
}

pub(crate) fn lanes_to_bytes<let NL: u32, let NB: u32>(lanes: [u64; NL]) -> [u8; NB] {
    let mut out: [u8; NB] = [0; NB];

    for i in 0..NL {
        let bytes: [u8; 8] = (lanes[i] as Field).to_le_bytes();

        for j in 0..8 {
            if i * 8 + j < NB {
                out[i * 8 + j] = bytes[j];
            }
        }
    }

    out
}

pub(crate) fn shake256_bytes<let N: u32, let OUT: u32>(input: [u8; N]) -> [u64; OUT] {
    squeeze::<SHAKE256_RATE, OUT>(absorb_bytes::<SHAKE256_RATE, N>(input))
}

pub(crate) fn shake256_lanes<let N: u32, let OUT: u32>(input: [u64; N]) -> [u64; OUT] {
    squeeze::<SHAKE256_RATE, OUT>(absorb_lanes::<SHAKE256_RATE, N>(input))
}

pub(crate) fn concat<let N: u32, let M: u32>(a: [u8; N], b: [u8; M]) -> [u8; N + M] {
    let mut out: [u8; N + M] = [0; N + M];

    for i in 0..N {
        out[i] = a[i];
    }

    for i in 0..M {
        out[N + i] = b[i];
    }

    out
}

mod tests {
    use super::{absorb_bytes, concat, lanes_to_bytes, SHAKE128_RATE, shake256_bytes, squeeze};

    // SHAKE256("", 32) and SHAKE256(0xa3 * 200, 32) from the NIST SHA-3 example values.
    #[test]
    fn shake256_known_answers() {
        let empty: [u8; 0] = [];

        let out: [u8; 32] = lanes_to_bytes(shake256_bytes::<0, 4>(empty));

        let expected: [u8; 32] = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f,
        ];

        assert(out == expected);

        let a3: [u8; 200] = [0xa3; 200];

        let out2: [u8; 32] = lanes_to_bytes(shake256_bytes::<200, 4>(a3));

        let expected2: [u8; 32] = [
            0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04, 0x07, 0xa2, 0x2d, 0x59, 0x28, 0x86,
            0x52, 0xe9, 0xd9, 0xf1, 0xa7, 0xee, 0x0c, 0x1e, 0x7c, 0x1c, 0xa6, 0x99, 0x42, 0x4d,
            0xa8, 0x4a, 0x90, 0x4d,
        ];

        assert(out2 == expected2);
    }

    // SHAKE128(0xa3 * 200, 32), checked against Python hashlib.
    #[test]
    fn shake128_known_answer() {
        let a3: [u8; 200] = [0xa3; 200];

        let out: [u8; 32] = lanes_to_bytes(squeeze::<SHAKE128_RATE, 4>(
            absorb_bytes::<SHAKE128_RATE, 200>(a3),
        ));

        let expected: [u8; 32] = [
            0x13, 0x1a, 0xb8, 0xd2, 0xb5, 0x94, 0x94, 0x6b, 0x9c, 0x81, 0x33, 0x3f, 0x9b, 0xb6,
            0xe0, 0xce, 0x75, 0xc3, 0xb9, 0x31, 0x04, 0xfa, 0x34, 0x69, 0xd3, 0x91, 0x74, 0x57,
            0x38, 0x5d, 0xa0, 0x37,
        ];

        assert(out == expected);
    }

    #[test]
    fn concat_orders_bytes() {
        assert(concat([1, 2], [3, 4, 5]) == [1, 2, 3, 4, 5]);
    }
}
