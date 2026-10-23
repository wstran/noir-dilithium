#!/usr/bin/env bash
# Runs the unit tests and every vector suite. Needs nargo (1.0.0-rc.6) and python3 on PATH.
#
#   scripts/test.sh                 unit tests plus all vector suites as unconstrained (Brillig) tests
#   CONSTRAINED=1 scripts/test.sh   the vector suites as constrained tests (ACIR witness generation, slow)
#   SUITES="malformed prepared"     run only these vector suites
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

GEN=${GEN_DIR:-$(mktemp -d)}

THREADS=${TEST_THREADS:-2}

(cd "$ROOT" && nargo test --package dilithium)

if [ "${CONSTRAINED:-0}" = "1" ]; then
    python3 -I "$ROOT/scripts/gen_tests.py" "$GEN" --constrained
else
    python3 -I "$ROOT/scripts/gen_tests.py" "$GEN"
fi

for suite in ${SUITES:-malformed prepared edge tampered_r3 acvp_mldsa65 kat_r3}; do
    (cd "$GEN/$suite" && nargo test --test-threads "$THREADS")
done
