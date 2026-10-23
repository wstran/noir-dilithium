#!/usr/bin/env bash
# Benchmarks one bench package with nargo and bb on PATH (tested with nargo 1.0.0-rc.6 and bb 6.0.0).
#
#   scripts/bench.sh compile PKG    compile, gate count (bb gates) and verification key
#   scripts/bench.sh execute PKG    witness generation (nargo execute)
#   scripts/bench.sh prove PKG      UltraHonk proof with -t noir-recursive-no-zk, then bb verify
#
# Every step prints one MEASURE line. Inside a container, CPU time and peak memory come from cgroup v2 and the
# peak covers the whole container, so run each step in a fresh container (scripts/bench_docker.sh does).
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

STEP=${1:?step}

PKG=${2:?package}

DIR=$ROOT/bench/$PKG

OUT=$ROOT/bench/out/$PKG

TARGET=noir-recursive-no-zk

cpu_usec() {
    if [ -r /sys/fs/cgroup/cpu.stat ]; then awk '/usage_usec/ {print $2}' /sys/fs/cgroup/cpu.stat; else echo 0; fi
}

peak_mib() {
    if [ -r /sys/fs/cgroup/memory.peak ]; then echo $(( $(cat /sys/fs/cgroup/memory.peak) / 1048576 )); else echo NA; fi
}

measure() {
    local label=$1

    shift

    local c0

    c0=$(cpu_usec)

    local s

    s=$(date +%s%N)

    "$@" > "$OUT/$label.log" 2>&1

    local rc=$?

    local wall=$(( ($(date +%s%N) - s) / 1000000 ))

    local cpu=$(( ($(cpu_usec) - c0) / 1000 ))

    echo "MEASURE $PKG $label exit=$rc wall_ms=$wall cpu_ms=$cpu peak_mib=$(peak_mib)"

    return $rc
}

mkdir -p "$OUT"

cd "$DIR"

case $STEP in
    compile)
        measure compile nargo compile --silence-warnings || exit 1

        gates=$(bb gates -b "$ROOT/target/$PKG.json" 2>/dev/null | grep -o '"circuit_size": *[0-9]*' | grep -o '[0-9]*$')

        echo "GATES $PKG $gates"

        measure write_vk bb write_vk -b "$ROOT/target/$PKG.json" -o "$OUT/vk" -t $TARGET
        ;;
    execute)
        measure execute nargo execute --silence-warnings "$PKG"
        ;;
    prove)
        measure prove bb prove -b "$ROOT/target/$PKG.json" -w "$ROOT/target/$PKG.gz" -k "$OUT/vk/vk" -o "$OUT/proof" -t $TARGET || exit 1

        bb verify -p "$OUT/proof/proof" -k "$OUT/vk/vk" -i "$OUT/proof/public_inputs" -t $TARGET > "$OUT/verify.log" 2>&1 && verified=yes || verified=no

        echo "PROOF $PKG bytes=$(stat -c %s "$OUT/proof/proof") verified=$verified"
        ;;
    *)
        echo "unknown step $STEP" >&2

        exit 2
        ;;
esac
