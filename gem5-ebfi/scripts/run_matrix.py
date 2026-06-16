#!/usr/bin/env python3

import argparse
import csv
import itertools
import json
import math
import statistics
import subprocess
from pathlib import Path


MODES = ("baseline", "optimistic", "verified")


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
        default=project_dir / "results" / "runs",
    )
    parser.add_argument("--seeds", default="1,2,3,4,5")
    parser.add_argument("--working-sets-kib", default="256,4096,65536")
    parser.add_argument("--periods-ns", default="20,100")
    parser.add_argument("--warmup-us", type=float, default=100.0)
    parser.add_argument("--duration-us", type=float, default=500.0)
    parser.add_argument("--read-percent", type=int, default=80)
    parser.add_argument(
        "--traffic-patterns",
        default="uniform",
        help="comma-separated: uniform,linear,stride4k,hotcold",
    )
    parser.add_argument("--cxl-one-way-ns", type=float, default=50.0)
    parser.add_argument("--memory-latency-ns", type=float, default=100.0)
    parser.add_argument("--aead-latency-ns", type=float, default=25.0)
    parser.add_argument("--aead-issue-ns", type=float, default=4.0)
    parser.add_argument("--metadata-entries", type=int, default=4096)
    parser.add_argument("--metadata-hit-ns", type=float, default=4.0)
    parser.add_argument("--metadata-miss-ns", type=float, default=80.0)
    parser.add_argument("--metadata-issue-ns", type=float, default=2.0)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def comma_ints(value):
    return [int(part) for part in value.split(",") if part]


def comma_floats(value):
    return [float(part) for part in value.split(",") if part]


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


def extract_row(run_dir, mode, seed, working_set, period, traffic_pattern):
    stats = parse_stats(run_dir / "stats.txt")
    reads = stat(stats, "tgen.totalReads")
    writes = stat(stats, "tgen.totalWrites")
    read_ticks = stat(stats, "tgen.totalReadLatency")
    write_ticks = stat(stats, "tgen.totalWriteLatency")
    hits = stat(stats, "ebfi.metadataHits")
    misses = stat(stats, "ebfi.metadataMisses")
    late_checks = stat(stats, "ebfi.optimisticLateChecks")
    late_ticks = stat(stats, "ebfi.optimisticLateCheckTicks")
    return {
        "mode": mode,
        "seed": seed,
        "working_set_kib": working_set,
        "request_period_ns": period,
        "traffic_pattern": traffic_pattern,
        "reads": int(reads),
        "writes": int(writes),
        "avg_read_latency_ns": read_ticks / reads / 1000 if reads else 0.0,
        "avg_write_latency_ns": write_ticks / writes / 1000 if writes else 0.0,
        "metadata_hit_rate_pct": (
            100.0 * hits / (hits + misses) if hits + misses else 0.0
        ),
        "aead_queue_ns_per_op": (
            stat(stats, "ebfi.aeadQueueTicks") / (reads + writes) / 1000
            if reads + writes
            else 0.0
        ),
        "metadata_queue_ns_per_read": (
            stat(stats, "ebfi.metadataQueueTicks") / reads / 1000
            if reads
            else 0.0
        ),
        "late_check_rate_pct": 100.0 * late_checks / reads if reads else 0.0,
        "late_check_window_ns": (
            late_ticks / late_checks / 1000 if late_checks else 0.0
        ),
        "ratchets": int(stat(stats, "ebfi.ratchets")),
    }


def mean_ci95(values):
    mean = statistics.fmean(values)
    if len(values) < 2:
        return mean, 0.0
    return mean, 1.96 * statistics.stdev(values) / math.sqrt(len(values))


def write_outputs(rows, result_dir):
    result_dir.mkdir(parents=True, exist_ok=True)
    baselines = {
        (
            row["seed"],
            row["working_set_kib"],
            row["request_period_ns"],
            row["traffic_pattern"],
        ): row["avg_read_latency_ns"]
        for row in rows
        if row["mode"] == "baseline"
    }
    for row in rows:
        base = baselines[
            (
                row["seed"],
                row["working_set_kib"],
                row["request_period_ns"],
                row["traffic_pattern"],
            )
        ]
        row["read_overhead_pct"] = (
            100.0 * (row["avg_read_latency_ns"] - base) / base
        )

    raw_path = result_dir / "raw_results.csv"
    with raw_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    grouped = {}
    for row in rows:
        key = (
            row["mode"],
            row["working_set_kib"],
            row["request_period_ns"],
            row["traffic_pattern"],
        )
        grouped.setdefault(key, []).append(row)

    summary = []
    metrics = (
        "avg_read_latency_ns",
        "read_overhead_pct",
        "metadata_hit_rate_pct",
        "aead_queue_ns_per_op",
        "metadata_queue_ns_per_read",
        "late_check_rate_pct",
        "late_check_window_ns",
    )
    for key, group in sorted(grouped.items()):
        entry = {
            "mode": key[0],
            "working_set_kib": key[1],
            "request_period_ns": key[2],
            "traffic_pattern": key[3],
            "seeds": len(group),
        }
        for metric in metrics:
            mean, ci95 = mean_ci95([row[metric] for row in group])
            entry[f"{metric}_mean"] = mean
            entry[f"{metric}_ci95"] = ci95
        summary.append(entry)

    with (result_dir / "summary.json").open("w") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)

    summary_path = result_dir / "summary.csv"
    with summary_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)


def main():
    args = parse_args()
    args.gem5 = args.gem5.resolve()
    args.config = args.config.resolve()
    seeds = comma_ints(args.seeds)
    working_sets = comma_ints(args.working_sets_kib)
    periods = comma_floats(args.periods_ns)
    traffic_patterns = [
        part for part in args.traffic_patterns.split(",") if part
    ]
    valid_patterns = {"uniform", "linear", "stride4k", "hotcold"}
    unknown_patterns = set(traffic_patterns) - valid_patterns
    if unknown_patterns:
        raise ValueError(f"unknown traffic patterns: {sorted(unknown_patterns)}")
    args.out_root.mkdir(parents=True, exist_ok=True)

    rows = []
    cases = list(itertools.product(
        MODES, seeds, working_sets, periods, traffic_patterns
    ))
    for index, (mode, seed, working_set, period, traffic_pattern) in enumerate(
        cases, 1
    ):
        label = (
            f"{mode}-{traffic_pattern}-seed{seed}-ws{working_set}k-"
            f"period{period:g}ns"
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
                f"--traffic-pattern={traffic_pattern}",
                f"--cxl-one-way-ns={args.cxl_one_way_ns}",
                f"--memory-latency-ns={args.memory_latency_ns}",
                f"--aead-latency-ns={args.aead_latency_ns}",
                f"--aead-issue-ns={args.aead_issue_ns}",
                f"--metadata-entries={args.metadata_entries}",
                f"--metadata-hit-ns={args.metadata_hit_ns}",
                f"--metadata-miss-ns={args.metadata_miss_ns}",
                f"--metadata-issue-ns={args.metadata_issue_ns}",
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
            extract_row(
                run_dir, mode, seed, working_set, period, traffic_pattern
            )
        )

    write_outputs(rows, args.out_root.parent)
    print(f"Wrote {args.out_root.parent / 'summary.json'}")


if __name__ == "__main__":
    main()
