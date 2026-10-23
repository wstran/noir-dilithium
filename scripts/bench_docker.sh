#!/usr/bin/env bash
# Runs scripts/bench.sh for every bench package, each step in a fresh ubuntu:24.04 container, and prints the
# median of RUNS runs. NARGO_TARBALL and BB_TARBALL point at the release archives for aarch64 or x86_64 Linux.
#
#   NARGO_TARBALL=... BB_TARBALL=... scripts/bench_docker.sh [package ...]
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

: "${NARGO_TARBALL:?path to noir-<arch>-unknown-linux-gnu.tar.gz (1.0.0-rc.6)}"

: "${BB_TARBALL:?path to barretenberg-<arch>-linux.tar.gz (6.0.0)}"

RUNS=${RUNS:-3}

MEMORY=${MEMORY:-13g}

CPUS=${CPUS:-6}

PACKAGES=${*:-r3_verify_prepared r3_verify r3_prepare_key r3_key_commitment mldsa65_verify_prepared mldsa65_verify mldsa65_prepare_key}

PROVE=${PROVE:-r3_verify_prepared r3_verify mldsa65_verify_prepared mldsa65_verify}

# bb keeps its structured reference string in $HOME/.bb-crs; a persistent copy keeps downloads out of the timings.
CRS=${BB_CRS_DIR:-$ROOT/bench/out/bb-crs}

mkdir -p "$CRS"

RESULTS=$ROOT/bench/out/results.txt

mkdir -p "$ROOT/bench/out"

: > "$RESULTS"

step() {
    docker run --rm --cap-drop ALL --security-opt no-new-privileges --user "$(id -u):$(id -g)" --memory "$MEMORY" --cpus "$CPUS" \
        -v "$ROOT:/r" -v "$NARGO_TARBALL:/tools/nargo.tar.gz:ro" -v "$BB_TARBALL:/tools/bb.tar.gz:ro" -v "$CRS:/tmp/.bb-crs" -e HOME=/tmp ubuntu:24.04 \
        bash -c 'mkdir -p /tmp/bin && tar -xzf /tools/nargo.tar.gz -C /tmp/bin && tar -xzf /tools/bb.tar.gz -C /tmp/bin && PATH=/tmp/bin:$PATH /r/scripts/bench.sh '"$1 $2" | tee -a "$RESULTS"
}

for pkg in $PACKAGES; do
    step compile "$pkg"

    for _ in $(seq "$RUNS"); do
        step execute "$pkg"
    done

    if [[ " $PROVE " == *" $pkg "* ]]; then
        for _ in $(seq "$RUNS"); do
            step prove "$pkg"
        done
    fi
done

echo

docker run --rm --cap-drop ALL --security-opt no-new-privileges --user "$(id -u):$(id -g)" -v "$ROOT:/r:ro" python:3.12-slim python3 -I /r/scripts/bench_summary.py /r/bench/out/results.txt
