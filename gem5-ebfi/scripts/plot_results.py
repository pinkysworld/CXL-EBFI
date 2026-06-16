#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt


def parse_args():
    project = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        type=Path,
        default=project / "results" / "summary.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project / "results" / "gem5_ebfi_overhead.pdf",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    data = json.loads(args.summary.read_text())
    periods = sorted({row["request_period_ns"] for row in data})
    worksets = sorted({row["working_set_kib"] for row in data})
    modes = ("optimistic", "verified")
    colors = {"optimistic": "#4C72B0", "verified": "#DD8452"}

    fig, axes = plt.subplots(1, len(periods), figsize=(7.2, 2.8), sharey=True)
    if len(periods) == 1:
        axes = [axes]

    for axis, period in zip(axes, periods):
        x = range(len(worksets))
        width = 0.36
        for offset, mode in enumerate(modes):
            rows = {
                row["working_set_kib"]: row
                for row in data
                if row["mode"] == mode
                and row["request_period_ns"] == period
            }
            values = [
                rows[ws]["read_overhead_pct_mean"] for ws in worksets
            ]
            errors = [
                rows[ws]["read_overhead_pct_ci95"] for ws in worksets
            ]
            positions = [
                value + (offset - 0.5) * width for value in x
            ]
            axis.bar(
                positions,
                values,
                width,
                yerr=errors,
                label=mode.capitalize(),
                color=colors[mode],
                capsize=2,
            )
        axis.set_title(f"Request period {period:g} ns")
        axis.set_xticks(list(x))
        axis.set_xticklabels(
            [f"{ws / 1024:g} MiB" if ws >= 1024 else f"{ws} KiB"
             for ws in worksets]
        )
        axis.set_xlabel("Working set")
        axis.grid(axis="y", alpha=0.25)

    axes[0].set_ylabel("Read-latency overhead (%)")
    axes[-1].legend(frameon=False)
    fig.tight_layout()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, bbox_inches="tight")
    print(args.output)


if __name__ == "__main__":
    main()

