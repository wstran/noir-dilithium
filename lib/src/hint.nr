global ALPHA: Field = 523776;

unconstrained fn decompose_hint(r: Field) -> (Field, Field) {
    let v = r as u64;

    let m = v % 523776;

    if m <= 261888 {
        (((v - m) / 523776) as Field, (m + 261887) as Field)
    } else {
        (((v - m) / 523776 + 1) as Field, (m - 261889) as Field)
    }
}

// UseHint for alpha = 2 * gamma2 = (q - 1) / 16, for 0 <= r < q.
pub(crate) fn use_hint(hint: Field, r: Field) -> Field {
    // Safety: r1n <= 16 and 0 <= u <= alpha - 1 are range-checked and r == r1n * alpha + u - (alpha / 2 - 1) is
    // asserted; for r < q this is the unique decomposition with r0 = u - (alpha / 2 - 1) in (-alpha / 2, alpha / 2].
    let (r1n, u) = unsafe { decompose_hint(r) };

    (16 - r1n).assert_max_bit_size::<5>();

    u.assert_max_bit_size::<19>();

    (523775 - u).assert_max_bit_size::<19>();

    assert(r1n * ALPHA + u - 261887 == r);

    // r - r0 == q - 1: Decompose returns r1 = 0 and r0 - 1, which is negative.
    let special = r1n == 16;

    let r1 = if special { 0 } else { r1n };

    let positive = !special & ((u as u32) > 261887);

    let up = if r1 == 15 { 0 } else { r1 + 1 };

    let down = if r1 == 0 { 15 } else { r1 - 1 };

    let hinted = if positive { up } else { down };

    if hint == 1 {
        hinted
    } else {
        r1
    }
}

mod tests {
    use crate::hint_cases::USE_HINT_CASES;
    use super::use_hint;

    // Expected values from a Python transcription of FIPS 204 Algorithms 36 and 40, on the decomposition
    // boundaries, including r = 8118529 where r - r0 == q - 1 and r0 - 1 == -261888.
    #[test]
    fn use_hint_boundaries() {
        let cases: [(Field, Field, Field); 16] = [
            (0, 0, 0),
            (0, 1, 15),
            (261888, 0, 0),
            (261888, 1, 1),
            (261889, 0, 1),
            (261889, 1, 0),
            (523776, 0, 1),
            (523776, 1, 0),
            (785664, 1, 2),
            (785665, 1, 1),
            (8118528, 1, 0),
            (8118529, 0, 0),
            (8118529, 1, 15),
            (8380416, 0, 0),
            (8380416, 1, 15),
            (7856640, 1, 14),
        ];

        for i in 0..16 {
            let (r, h, expected) = cases[i];

            assert(use_hint(h, r) == expected);
        }
    }

    // Every decomposition boundary and a seeded random sample, against FIPS 204 Algorithms 36 and 40
    // (scripts/gen_use_hint_cases.py). scripts/check/use_hint.sh checks all r < q against the reference.
    #[test]
    fn use_hint_boundaries_and_random_sample() {
        for i in 0..USE_HINT_CASES.len() {
            let (r, h, expected) = USE_HINT_CASES[i];

            assert(use_hint(h, r) == expected);
        }
    }

    #[test]
    unconstrained fn use_hint_boundaries_and_random_sample_unconstrained() {
        for i in 0..USE_HINT_CASES.len() {
            let (r, h, expected) = USE_HINT_CASES[i];

            assert(use_hint(h, r) == expected);
        }
    }
}
