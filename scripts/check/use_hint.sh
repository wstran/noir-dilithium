#!/usr/bin/env bash
# Builds and runs scripts/check/use_hint.c against the pq-crystals reference at tag v3.1 (exhaustive over r < q).
# OLD_RULE=1 replays the earlier circuit's sign test instead, to show that the check detects its error.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)

WORK=$(mktemp -d)

curl -sSL -o "$WORK/v3.1.tar.gz" https://github.com/pq-crystals/dilithium/archive/refs/tags/v3.1.tar.gz

echo "97f22c4a39668a1abca55e1369384ed65cd9a755f60755badd4ea81cb16a6384  $WORK/v3.1.tar.gz" | sha256sum -c - > /dev/null

tar -xzf "$WORK/v3.1.tar.gz" -C "$WORK"

REF=$WORK/dilithium-3.1/ref

FLAGS=""

if [ "${OLD_RULE:-0}" = "1" ]; then
    FLAGS="-DOLD_RULE"
fi

cc -O2 -DDILITHIUM_MODE=3 $FLAGS -I"$REF" -o "$WORK/use_hint" "$HERE/use_hint.c" "$REF/rounding.c"

"$WORK/use_hint"
