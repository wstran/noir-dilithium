"""Summarizes bench/out/results.txt written by scripts/bench_docker.sh as a Markdown table of medians."""
import statistics
import sys


def parse(path):
    rows = {}

    for line in open(path):
        p = line.split()

        if not p:
            continue

        if p[0] == "GATES":
            rows.setdefault(p[1], {})["gates"] = p[2]
        elif p[0] == "MEASURE":
            kv = dict(x.split("=") for x in p[3:])

            rows.setdefault(p[1], {}).setdefault(p[2], []).append((int(kv["wall_ms"]), int(kv["cpu_ms"]), kv["peak_mib"]))
        elif p[0] == "PROOF":
            kv = dict(x.split("=") for x in p[2:])

            rows.setdefault(p[1], {})["proof"] = f"{kv['bytes']} B, verified {kv['verified']}"

    return rows


def median(runs, i):
    return statistics.median(r[i] for r in runs)


def main():
    rows = parse(sys.argv[1])

    print("| package | gates | witness, median s | prove wall / CPU, median s | prove peak MiB | proof |")

    print("|---|---|---|---|---|---|")

    for pkg, r in rows.items():
        ex = r.get("execute", [])

        pr = r.get("prove", [])

        witness = f"{median(ex, 0) / 1000:.2f}" if ex else "-"

        prove = f"{median(pr, 0) / 1000:.2f} / {median(pr, 1) / 1000:.1f}" if pr else "-"

        peak = max(int(x[2]) for x in pr) if pr else "-"

        print(f"| {pkg} | {r.get('gates', '-')} | {witness} | {prove} | {peak} | {r.get('proof', '-')} |")


if __name__ == "__main__":
    main()
