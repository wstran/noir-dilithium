/*
 * Exhaustive check of the library's UseHint for gamma2 = (q - 1) / 32: for every 0 <= r < q and h in {0, 1},
 * a line-by-line replay of lib/src/hint.nr (the unconstrained decomposition and every in-circuit assertion)
 * must satisfy its constraints and agree with the pq-crystals round 3 reference use_hint (ref/rounding.c,
 * DILITHIUM_MODE=3) and with a direct transcription of FIPS 204 Algorithms 36 and 40.
 */
#include <stdint.h>
#include <stdio.h>
#include "params.h"
#include "rounding.h"

static int64_t noir_use_hint(int64_t h, int64_t r, int *constraints_ok) {
    uint64_t v = (uint64_t)r;

    uint64_t m = v % 523776;

    int64_t r1n, u;

    if (m <= 261888) {
        r1n = (int64_t)((v - m) / 523776);

        u = (int64_t)(m + 261887);
    } else {
        r1n = (int64_t)((v - m) / 523776 + 1);

        u = (int64_t)(m - 261889);
    }

    *constraints_ok = (16 - r1n >= 0) && (16 - r1n < 32) && (u >= 0) && (u < (1 << 19)) && (523775 - u >= 0) && (523775 - u < (1 << 19)) && (r1n * 523776 + u - 261887 == r);

    int special = r1n == 16;

    int64_t r1 = special ? 0 : r1n;

#ifdef OLD_RULE
    /* The earlier circuit: positive = (u_adj as u32) > 261887 with u_adj = u - 1 in the wrap case, where the
       field element -1 truncates to 0xF0000000. */
    int64_t u_adj = special ? u - 1 : u;

    int positive = u_adj < 0 ? 1 : u_adj > 261887;
#else
    int positive = !special && u > 261887;
#endif

    int64_t up = r1 == 15 ? 0 : r1 + 1;

    int64_t down = r1 == 0 ? 15 : r1 - 1;

    int64_t hinted = positive ? up : down;

    return h == 1 ? hinted : r1;
}

static int64_t fips204_use_hint(int64_t h, int64_t r) {
    const int64_t q = 8380417, alpha = 523776;

    int64_t rp = ((r % q) + q) % q;

    int64_t r0 = rp % alpha;

    if (r0 > alpha / 2) {
        r0 -= alpha;
    }

    int64_t r1;

    if (rp - r0 == q - 1) {
        r1 = 0;

        r0 = r0 - 1;
    } else {
        r1 = (rp - r0) / alpha;
    }

    if (h == 1 && r0 > 0) {
        return (r1 + 1) % 16;
    }

    if (h == 1 && r0 <= 0) {
        return (r1 + 15) % 16;
    }

    return r1;
}

int main(void) {
    long checked = 0, mismatches = 0, unsatisfied = 0;

    for (int64_t h = 0; h <= 1; h++) {
        for (int64_t r = 0; r < Q; r++) {
            int ok;

            int64_t a = noir_use_hint(h, r, &ok);

            int64_t b = (int64_t)use_hint((int32_t)r, (unsigned int)h);

            int64_t c = fips204_use_hint(h, r);

            if (!ok) {
                unsatisfied++;
            }

            if (a != b || b != c) {
                if (mismatches < 10) {
                    printf("mismatch r=%lld h=%lld noir=%lld ref=%lld fips204=%lld\n", (long long)r, (long long)h, (long long)a, (long long)b, (long long)c);
                }

                mismatches++;
            }

            checked++;
        }
    }

    printf("checked %ld (r, h) pairs: %ld mismatches, %ld with unsatisfied constraints\n", checked, mismatches, unsatisfied);

    return (mismatches == 0 && unsatisfied == 0) ? 0 : 1;
}
