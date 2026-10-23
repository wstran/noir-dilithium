use crate::params::{GAMMA1, OMEGA, Q};

// t1 from the public key: 6 polynomials of 10-bit coefficients packed little-endian after rho.
pub(crate) fn decode_t1(pk: [u8; 1952]) -> [[Field; 256]; 6] {
    let mut t1: [[Field; 256]; 6] = [[0; 256]; 6];

    for p in 0..6 {
        for k in 0..64 {
            let base = 32 + p * 320 + k * 5;

            let b0 = pk[base] as Field;

            let b1 = pk[base + 1];

            let b2 = pk[base + 2];

            let b3 = pk[base + 3];

            let b4 = pk[base + 4] as Field;

            t1[p][4 * k] = b0 + ((b1 & 0x03) as Field) * 256;

            t1[p][4 * k + 1] = ((b1 >> 2) as Field) + ((b2 & 0x0F) as Field) * 64;

            t1[p][4 * k + 2] = ((b2 >> 4) as Field) + ((b3 & 0x3F) as Field) * 16;

            t1[p][4 * k + 3] = ((b3 >> 6) as Field) + b4 * 4;
        }
    }

    t1
}

// z from the signature, stored as gamma1 - v + q with v the 20-bit packed value. The flag is the norm check
// ||z||inf < gamma1 - beta, that is 197 <= v <= 1048379.
pub(crate) fn decode_z<let SIG: u32>(sig: [u8; SIG], offset: u32) -> ([[Field; 256]; 5], bool) {
    let mut z: [[Field; 256]; 5] = [[0; 256]; 5];

    let mut ok = true;

    for p in 0..5 {
        for k in 0..128 {
            let base = offset + p * 640 + k * 5;

            let b2 = sig[base + 2];

            let v0 = (sig[base] as Field)
                + (sig[base + 1] as Field) * 256
                + ((b2 & 0x0F) as Field) * 65536;

            let v1 = ((b2 >> 4) as Field)
                + (sig[base + 3] as Field) * 16
                + (sig[base + 4] as Field) * 4096;

            let u0 = v0 as u32;

            let u1 = v1 as u32;

            ok = ok & (u0 >= 197) & (u0 <= 1048379) & (u1 >= 197) & (u1 <= 1048379);

            z[p][2 * k] = GAMMA1 + Q - v0;

            z[p][2 * k + 1] = GAMMA1 + Q - v1;
        }
    }

    (z, ok)
}

// The hint vector from its OMEGA + K byte encoding. The flag is false for every encoding the reference
// rejects: decreasing or too large per-polynomial counts, positions that are not strictly increasing within
// a polynomial, and nonzero unused position bytes.
pub(crate) fn decode_hint<let SIG: u32>(sig: [u8; SIG]) -> ([Field; 1536], bool) {
    let hstart = SIG - 61;

    let mut ok = true;

    let mut offsets: [u32; 6] = [0; 6];

    for i in 0..6 {
        offsets[i] = sig[hstart + OMEGA + i] as u32;
    }

    for i in 0..5 {
        ok = ok & (offsets[i] <= offsets[i + 1]);
    }

    ok = ok & (offsets[5] <= OMEGA);

    let mut positions: [u32; 55] = [0; 55];

    for s in 0..55 {
        positions[s] = sig[hstart + s] as u32;

        ok = ok & ((s < offsets[5]) | (positions[s] == 0));
    }

    // Each polynomial's positions are merged in increasing order of x: a position that is repeated or out of
    // order is never consumed, so the pointer misses the polynomial's end offset.
    let mut h: [Field; 1536] = [0; 1536];

    let mut ptr: u32 = 0;

    for i in 0..6 {
        for x in 0..256 {
            let next = positions[if ptr < 55 { ptr } else { 54 }];

            let hit = (ptr < offsets[i]) & (next == x);

            if hit {
                h[i * 256 + x] = 1;

                ptr += 1;
            }
        }

        ok = ok & (ptr == offsets[i]);
    }

    (h, ok)
}

mod tests {
    use super::{decode_hint, decode_z};

    // A 3293-byte signature whose hint area holds the given positions and cumulative counts.
    fn with_hint(positions: [u8; 55], counts: [u8; 6]) -> [u8; 3293] {
        let mut sig: [u8; 3293] = [0; 3293];

        for i in 0..55 {
            sig[3232 + i] = positions[i];
        }

        for i in 0..6 {
            sig[3287 + i] = counts[i];
        }

        sig
    }

    #[test]
    fn hint_valid_encodings() {
        let mut positions: [u8; 55] = [0; 55];

        positions[0] = 3;

        positions[1] = 200;

        positions[2] = 0;

        positions[3] = 255;

        let (h, ok) = decode_hint(with_hint(positions, [2, 2, 4, 4, 4, 4]));

        assert(ok);

        assert((h[3] == 1) & (h[200] == 1) & (h[512] == 1) & (h[512 + 255] == 1));

        let mut sum: Field = 0;

        for i in 0..1536 {
            sum = sum + h[i];
        }

        assert(sum == 4);

        let (_, empty_ok) = decode_hint(with_hint([0; 55], [0; 6]));

        assert(empty_ok);

        let mut full: [u8; 55] = [0; 55];

        for i in 0..55 {
            full[i] = i as u8;
        }

        let (_, full_ok) = decode_hint(with_hint(full, [55, 55, 55, 55, 55, 55]));

        assert(full_ok);
    }

    #[test]
    fn hint_rejected_encodings() {
        let mut positions: [u8; 55] = [0; 55];

        positions[0] = 3;

        positions[1] = 200;

        // Repeated position inside one polynomial.
        let mut repeated = positions;

        repeated[1] = 3;

        let (_, ok1) = decode_hint(with_hint(repeated, [2, 2, 2, 2, 2, 2]));

        assert(!ok1);

        // Decreasing positions inside one polynomial.
        let mut decreasing = positions;

        decreasing[0] = 201;

        let (_, ok2) = decode_hint(with_hint(decreasing, [2, 2, 2, 2, 2, 2]));

        assert(!ok2);

        // The same positions split across two polynomials are fine.
        let (_, ok3) = decode_hint(with_hint(decreasing, [1, 2, 2, 2, 2, 2]));

        assert(ok3);

        // Decreasing cumulative counts.
        let (_, ok4) = decode_hint(with_hint(positions, [2, 1, 2, 2, 2, 2]));

        assert(!ok4);

        // More than omega hints in total.
        let (_, ok5) = decode_hint(with_hint(positions, [2, 2, 2, 2, 2, 56]));

        assert(!ok5);

        // Nonzero unused position byte.
        let mut padded = positions;

        padded[54] = 1;

        let (_, ok6) = decode_hint(with_hint(padded, [2, 2, 2, 2, 2, 2]));

        assert(!ok6);

        // Unused byte zero but a count beyond the positions actually present.
        let (_, ok7) = decode_hint(with_hint(positions, [3, 3, 3, 3, 3, 3]));

        assert(!ok7);
    }

    // A 3293-byte signature whose first z coefficient packs v (offset 32, low 20 bits of bytes 32..34).
    fn with_z0(v: u32) -> [u8; 3293] {
        let mut sig: [u8; 3293] = [0; 3293];

        for i in 0..3200 {
            // Every coefficient packed as v = 0x80000 (z = 0) by default: bytes 00 00 08 00 80.
            let r = i % 5;

            sig[32 + i] = if r == 2 {
                0x08
            } else if r == 4 {
                0x80
            } else {
                0
            };
        }

        sig[32] = (v & 0xFF) as u8;

        sig[33] = ((v >> 8) & 0xFF) as u8;

        sig[34] = (sig[34] & 0xF0) | ((v >> 16) as u8);

        sig
    }

    #[test]
    fn z_norm_boundaries() {
        let (z, ok) = decode_z(with_z0(197), 32);

        assert(ok);

        // z = gamma1 - v = gamma1 - beta - 1, stored as gamma1 - v + q.
        assert(z[0][0] == 524288 - 197 + 8380417);

        assert(z[0][1] == 8380417);

        let (_, ok_hi) = decode_z(with_z0(1048379), 32);

        assert(ok_hi);

        let (_, bad_lo) = decode_z(with_z0(196), 32);

        assert(!bad_lo);

        let (_, bad_hi) = decode_z(with_z0(1048380), 32);

        assert(!bad_hi);

        let (_, bad_zero) = decode_z(with_z0(0), 32);

        assert(!bad_zero);
    }
}
