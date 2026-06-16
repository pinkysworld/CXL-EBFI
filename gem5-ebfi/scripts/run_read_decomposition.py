#!/usr/bin/env python3

import argparse
import csv
import itertools
import json
import math
import statistics
import subprocess
from pathlib import Path


PROFILES = {
    "insecure": ("baseline", 0.0, 0.0),
    "anchor_only": ("verified", 0.0, 0.0),
    "anchor_aead": ("verified", 25.0, 4.0),
}


def parse_args():
    script_dir = Path(__file__).resolve().parent
    project_dir = script_dir.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--gem5", required=True, type=Path)
    parser.add_argument(
        "--config",
        type=Path,
        default=project_dir / "configs" / "ebfi_cxl.py",
    )
    parser.add_argument(
        "--out-root",
        type=Path,
        default=project_dir / "results" / "read-decomposition" / "runs",
    )
    parser.add_argument("--seeds", default="1,2,3,4,5")
    parser.add_argument("--working-sets-kib", default="256,4096,65536")
    parser.add_argument("--periods-ns", default="20,100")
    parser.add_argument("--warmup-us", type=float, default=100.0)
    parser.add_argument("--duration-us", type=float, default=500.0)
    parser.add_argument("--read-percent", type=int, default=80)
    parser.add_argument("--ticket-tve-ns", type=float, default=20.0)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def parse_stats(path):
    stats = {}
    with path.open() as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 2 or fields[0].startswith("-"):
                continue
            try:
                stats[fields[0]] = float(fields[1])
            except ValueError:
                continue
    return stats


def stat(stats, suffix, default=0.0):
    matches = [value for name, value in stats.items() if name.endswith(suffix)]
    if not matches:
        return default
    if len(matches) > 1:
        raise RuntimeError(f"ambiguous stat suffix {suffix}")
    return matches[0]


def mean_ci95(values):
    mean = statistics.fmean(values)
    if len(values) < 2:
        return mean, 0.0
    return mean, 1.96 * statistics.stdev(values) / math.sqrt(len(values))


def extract_row(run_dir, profile, seed, working_set, period):
    stats = parse_stats(run_dir / "stats.txt")
    reads = stat(stats, "tgen.totalReads")
    hits = stat(stats, "ebfi.metadataHits")
    misses = stat(stats, "ebfi.metadataMisses")
    return {
        "profile": profile,
        "seed": seed,
        "working_set_kib": working_set,
        "request_period_ns": period,
        "reads": int(reads),
        "avg_read_latency_ns": (
            stat(stats, "tgen.totalReadLatency") / reads / 1000
            if reads
            else 0.0
        ),
        "metadata_hit_rate_pct": (
            100.0 * hits / (hits + misses) if hits + misses else 0.0
        ),
    }


def write_outputs(rows, result_dir, ticket_tve_ns):
    index = {
        (
            row["profile"],
            row["seed"],
            row["working_set_kib"],
            row["request_period_ns"],
        ): row
        for row in rows
    }
    for row in rows:
        key = (row["seed"], row["working_set_kib"], row["request_period_ns"])
        insecure = index[("insecure", *key)]["avg_read_latency_ns"]
        anchor = index[("anchor_only", *key)]["avg_read_latency_ns"]
        aead = index[("anchor_aead", *key)]["avg_read_latency_ns"]
        row["overhead_vs_insecure_pct"] = (
            100.0 * (row["avg_read_latency_ns"] - insecure) / insecure
        )
        row["crypto_increment_vs_anchor_pct"] = (
            100.0 * (aead - anchor) / anchor
            if row["profile"] == "anchor_aead"
            else 0.0
        )
        row["ticket_increment_vs_anchor_aead_pct"] = (
            100.0 * ticket_tve_ns / aead
            if row["profile"] == "anchor_aead"
            else 0.0
        )
        row["illustrative_ebfi_increment_vs_anchor_pct"] = (
            100.0 * (aead + ticket_tve_ns - anchor) / anchor
            if row["profile"] == "anchor_aead"
            else 0.0
        )
        row["illustrative_ebfi_latency_ns"] = (
            aead + ticket_tve_ns
            if row["profile"] == "anchor_aead"
            else 0.0
        )

    result_dir.mkdir(parents=True, exist_ok=True)
    with (result_dir / "raw_results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    grouped = {}
    for row in rows:
        key = (
            row["profile"],
            row["working_set_kib"],
            row["request_period_ns"],
        )
        grouped.setdefault(key, []).append(row)

    metrics = (
        "avg_read_latency_ns",
        "metadata_hit_rate_pct",
        "overhead_vs_insecure_pct",
        "crypto_increment_vs_anchor_pct",
        "ticket_increment_vs_anchor_aead_pct",
        "illustrative_ebfi_increment_vs_anchor_pct",
        "illustrative_ebfi_latency_ns",
    )
    summary = []
    for key, group in sorted(grouped.items()):
        entry = {
            "profile": key[0],
            "working_set_kib": key[1],
            "request_period_ns": key[2],
            "seeds": len(group),
        }
        for metric in metrics:
            mean, ci95 = mean_ci95([row[metric] for row in group])
            entry[f"{metric}_mean"] = mean
            entry[f"{metric}_ci95"] = ci95
        summary.append(entry)

    with (result_dir / "summary.json").open("w") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
    with (result_dir / "summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)


def main():
    args = parse_args()
    args.gem5 = args.gem5.resolve()
    args.config = args.config.resolve()
    seeds = [int(value) for value in args.seeds.split(",") if value]
    working_sets = [
        int(value) for value in args.working_sets_kib.split(",") if value
    ]
    periods = [float(value) for value in args.periods_ns.split(",") if value]
    args.out_root.mkdir(parents=True, exist_ok=True)

    rows = []
    cases = list(itertools.product(
        PROFILES.items(), seeds, working_sets, periods
    ))
    for index, ((profile, values), seed, working_set, period) in enumerate(
        cases, 1
    ):
        mode, aead_ns, aead_issue_ns = values
        label = (
            f"{profile}-seed{seed}-ws{working_set}k-period{period:g}ns"
        )
        run_dir = args.out_root / label
        stats_path = run_dir / "stats.txt"
        if args.force or not stats_path.exists():
            run_dir.mkdir(parents=True, exist_ok=True)
            command = [
                str(args.gem5),
                "-d",
                str(run_dir),
                str(args.config),
                f"--mode={mode}",
                f"--seed={seed}",
                f"--working-set-kib={working_set}",
                f"--request-period-ns={period}",
                f"--warmup-us={args.warmup_us}",
                f"--duration-us={args.duration_us}",
                f"--read-percent={args.read_percent}",
                "--traffic-pattern=uniform",
                f"--aead-latency-ns={aead_ns}",
                f"--aead-issue-ns={aead_issue_ns}",
            ]
            print(f"[{index}/{len(cases)}] {label}", flush=True)
            with (run_dir / "command.json").open("w") as handle:
                json.dump(command, handle, indent=2)
            completed = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            (run_dir / "gem5.log").write_text(completed.stdout)
            if completed.returncode:
                raise RuntimeError(
                    f"{label} failed; see {run_dir / 'gem5.log'}"
                )
        rows.append(
            extract_row(run_dir, profile, seed, working_set, period)
        )

    write_outputs(rows, args.out_root.parent, args.ticket_tve_ns)
    print(f"Wrote {args.out_root.parent / 'summary.json'}")


if __name__ == "__main__":
    main()
