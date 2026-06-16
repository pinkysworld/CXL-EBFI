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
    "insecure": ("baseline", 0.0, 0.0, 2.0),
    "anchor_aead": ("verified", 0.0, 0.0, 2.0),
    "ebfi_low": ("verified", 5.0, 10.0, 2.0),
    "ebfi_nominal": ("verified", 10.0, 20.0, 2.0),
    "ebfi_high": ("verified", 20.0, 40.0, 2.0),
    "ebfi_slow200_pipe": ("verified", 200.0, 200.0, 2.0),
    "ebfi_slow1000_pipe": ("verified", 1000.0, 1000.0, 2.0),
    "ebfi_slow200_serial": ("verified", 200.0, 200.0, 200.0),
    "ebfi_slow1000_serial": ("verified", 1000.0, 1000.0, 1000.0),
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
        default=project_dir / "results" / "write-path" / "runs",
    )
    parser.add_argument("--seeds", default="1,2,3,4,5")
    parser.add_argument("--periods-ns", default="20,100")
    parser.add_argument("--working-set-kib", type=int, default=65536)
    parser.add_argument("--warmup-us", type=float, default=100.0)
    parser.add_argument("--duration-us", type=float, default=500.0)
    parser.add_argument("--read-percent", type=int, default=80)
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


def extract_row(
    run_dir,
    profile,
    seed,
    period,
    reservation_ns,
    commit_ns,
    issue_ns,
    duration_us,
):
    stats = parse_stats(run_dir / "stats.txt")
    writes = stat(stats, "tgen.totalWrites")
    issued_writes = stat(stats, "ebfi.writes")
    write_ticks = stat(stats, "tgen.totalWriteLatency")
    return {
        "profile": profile,
        "seed": seed,
        "request_period_ns": period,
        "reservation_ns": reservation_ns,
        "commit_ns": commit_ns,
        "issue_ns": issue_ns,
        "writes": int(writes),
        "issued_writes": int(issued_writes),
        "completion_fraction_pct": (
            100.0 * writes / issued_writes if issued_writes else 0.0
        ),
        "completed_writes_per_us": writes / duration_us,
        "avg_write_latency_ns": write_ticks / writes / 1000 if writes else 0.0,
        "write_control_queue_ns_per_write": (
            stat(stats, "ebfi.writeControlQueueTicks") / issued_writes / 1000
            if issued_writes
            else 0.0
        ),
        "reservation_ns_per_write": (
            stat(stats, "ebfi.writeReservationTicks") / issued_writes / 1000
            if issued_writes
            else 0.0
        ),
        "commit_ns_per_write": (
            stat(stats, "ebfi.writeCommitTicks") / writes / 1000
            if writes
            else 0.0
        ),
    }


def write_outputs(rows, result_dir):
    insecure = {
        (row["seed"], row["request_period_ns"]): row["avg_write_latency_ns"]
        for row in rows
        if row["profile"] == "insecure"
    }
    anchor_aead = {
        (row["seed"], row["request_period_ns"]): row["avg_write_latency_ns"]
        for row in rows
        if row["profile"] == "anchor_aead"
    }
    for row in rows:
        key = (row["seed"], row["request_period_ns"])
        base = insecure[key]
        anchor = anchor_aead[key]
        row["write_overhead_vs_insecure_pct"] = (
            100.0 * (row["avg_write_latency_ns"] - base) / base
        )
        row["control_increment_vs_anchor_pct"] = (
            100.0 * (row["avg_write_latency_ns"] - anchor) / anchor
            if row["profile"].startswith("ebfi_")
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
            row["request_period_ns"],
            row["reservation_ns"],
            row["commit_ns"],
            row["issue_ns"],
        )
        grouped.setdefault(key, []).append(row)

    metrics = (
        "avg_write_latency_ns",
        "completed_writes_per_us",
        "completion_fraction_pct",
        "write_overhead_vs_insecure_pct",
        "control_increment_vs_anchor_pct",
        "write_control_queue_ns_per_write",
        "reservation_ns_per_write",
        "commit_ns_per_write",
    )
    summary = []
    for key, group in sorted(grouped.items()):
        entry = {
            "profile": key[0],
            "request_period_ns": key[1],
            "reservation_ns": key[2],
            "commit_ns": key[3],
            "issue_ns": key[4],
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
    periods = [float(value) for value in args.periods_ns.split(",") if value]
    args.out_root.mkdir(parents=True, exist_ok=True)

    rows = []
    cases = list(itertools.product(PROFILES.items(), seeds, periods))
    for index, ((profile, values), seed, period) in enumerate(cases, 1):
        mode, reservation_ns, commit_ns, issue_ns = values
        label = f"{profile}-seed{seed}-period{period:g}ns"
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
                f"--working-set-kib={args.working_set_kib}",
                f"--request-period-ns={period}",
                f"--warmup-us={args.warmup_us}",
                f"--duration-us={args.duration_us}",
                f"--read-percent={args.read_percent}",
                "--traffic-pattern=uniform",
                f"--write-reservation-ns={reservation_ns}",
                f"--write-commit-ns={commit_ns}",
                f"--write-control-issue-ns={issue_ns}",
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
                run_dir,
                profile,
                seed,
                period,
                reservation_ns,
                commit_ns,
                issue_ns,
                args.duration_us,
            )
        )

    write_outputs(rows, args.out_root.parent)
    print(f"Wrote {args.out_root.parent / 'summary.json'}")


if __name__ == "__main__":
    main()
