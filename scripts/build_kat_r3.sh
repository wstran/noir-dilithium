#!/usr/bin/env bash
# Rebuilds the Dilithium3 round 3 KAT file from the pq-crystals reference at tag v3.1 and checks the build with
# the reference's own test-vector hash. Needs curl, a C compiler and libcrypto (OpenSSL) headers.
#
#   scripts/build_kat_r3.sh OUT_DIR    writes OUT_DIR/PQCsignKAT_Dilithium3.rsp
set -euo pipefail

OUT=$(mkdir -p "$1" && cd "$1" && pwd)

WORK=$(mktemp -d)

curl -sSL -o "$WORK/v3.1.tar.gz" https://github.com/pq-crystals/dilithium/archive/refs/tags/v3.1.tar.gz

echo "97f22c4a39668a1abca55e1369384ed65cd9a755f60755badd4ea81cb16a6384  $WORK/v3.1.tar.gz" | sha256sum -c -

tar -xzf "$WORK/v3.1.tar.gz" -C "$WORK"

cd "$WORK"/dilithium-3.1/ref

make PQCgenKAT_sign3 test/test_vectors3 > /dev/null

./test/test_vectors3 > "$WORK/tvecs3"

grep ' tvecs3$' ../SHA256SUMS | sed "s|tvecs3|$WORK/tvecs3|" | sha256sum -c -

cd "$OUT"

"$WORK"/dilithium-3.1/ref/PQCgenKAT_sign3 > /dev/null

sha256sum PQCsignKAT_Dilithium3.rsp
