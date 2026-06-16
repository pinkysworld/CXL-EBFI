#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt


def main():
    project = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        type=Path,
        default=project / "results" / "workloads" / "summary.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project / "results" / "workloads" / "workload_overhead.pdf",
    )
    args = parser.parse_args()

    rows = json.loads(args.summary.read_text())
    patterns = ("uniform", "linear", "stride4k", "hotcold")
    labels = ("Uniform", "Linear", "4 KiB stride", "Hot/cold")
    modes = ("optimistic", "verified")
    colors = {"optimistic": "#4C72B0", "verified": "#DD8452"}

    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.8))
    x = range(len(patterns))
    width = 0.36
    for offset, mode in enumerate(modes):
        by_pattern = {
            row["traffic_pattern"]: row
            for row in rows
            if row["mode"] == mode
        }
        positions = [value + (offset - 0.5) * width for value in x]
        axes[0].bar(
            positions,
            [by_pattern[p]["read_overhead_pct_mean"] for p in patterns],
            width,
            yerr=[by_pattern[p]["read_overhead_pct_ci95"] for p in patterns],
            label=mode.capitalize(),
            color=colors[mode],
            capsize=2,
        )
        axes[1].bar(
            positions,
            [by_pattern[p]["metadata_hit_rate_pct_mean"] for p in patterns],
            width,
            yerr=[
                by_pattern[p]["metadata_hit_rate_pct_ci95"]
                for p in patterns
            ],
            label=mode.capitalize(),
            color=colors[mode],
            capsize=2,
        )

    axes[0].set_ylabel("Read-latency overhead (%)")
    axes[1].set_ylabel("Metadata hit rate (%)")
    for axis in axes:
        axis.set_xticks(list(x))
        axis.set_xticklabels(labels, rotation=20, ha="right")
        axis.grid(axis="y", alpha=0.25)
    axes[0].legend(frameon=False)
    fig.tight_layout()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, bbox_inches="tight")
    print(args.output)


if __name__ == "__main__":
    main()
