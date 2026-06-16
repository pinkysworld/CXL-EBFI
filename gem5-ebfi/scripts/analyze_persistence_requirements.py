#!/usr/bin/env python3

import argparse
import csv
import json
import math
from pathlib import Path


def parse_args():
    script_dir = Path(__file__).resolve().parent
    project_dir = script_dir.parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        type=Path,
        default=project_dir / "results" / "write-path" / "summary.csv",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=(
            project_dir
            / "results"
            / "write-path"
            / "persistence_requirements.csv"
        ),
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=(
            project_dir
            / "results"
            / "write-path"
            / "persistence_requirements.json"
        ),
    )
    parser.add_argument("--latencies-ns", default="200,1000")
    return parser.parse_args()


def main():
    args = parse_args()
    latencies = [
        float(value) for value in args.latencies_ns.split(",") if value
    ]
    with args.summary.open() as handle:
        summary = list(csv.DictReader(handle))

    offered_loads = [
        row for row in summary if row["profile"] == "anchor_aead"
    ]
    rows = []
    for load in offered_loads:
        write_rate = float(load["completed_writes_per_us_mean"])
        max_issue_ns = 1000.0 / (2.0 * write_rate)
        for latency_ns in latencies:
            min_parallel_depth = math.ceil(latency_ns / max_issue_ns)
            min_group_size = math.ceil(
                2.0 * (latency_ns / 1000.0) * write_rate
            )
            rows.append(
                {
                    "request_period_ns": float(load["request_period_ns"]),
                    "offered_writes_per_us": write_rate,
                    "persistence_latency_ns": latency_ns,
                    "max_shared_issue_interval_ns": max_issue_ns,
                    "min_inflight_operations": min_parallel_depth,
                    "min_group_commit_writes": min_group_size,
                    "serial_capacity_writes_per_us": (
                        1000.0 / (2.0 * latency_ns)
                    ),
                }
            )

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with args.out_json.open("w") as handle:
        json.dump(rows, handle, indent=2, sort_keys=True)

    print(f"Wrote {args.out_csv}")
    print(f"Wrote {args.out_json}")


if __name__ == "__main__":
    main()
