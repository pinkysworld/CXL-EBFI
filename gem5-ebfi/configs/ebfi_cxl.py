#!/usr/bin/env python3

import argparse
import json
import os

import m5
from m5.objects import (
    AddrRange,
    Bridge,
    CommMonitor,
    EbfiController,
    PyTrafficGen,
    Root,
    SimpleMemory,
    SrcClockDomain,
    System,
    SystemXBar,
    VoltageDomain,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cycle-level CXL-EBFI memory-path experiment"
    )
    parser.add_argument(
        "--mode",
        choices=("baseline", "optimistic", "verified"),
        default="baseline",
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--warmup-us", type=float, default=100.0)
    parser.add_argument("--duration-us", type=float, default=500.0)
    parser.add_argument("--drain-us", type=float, default=5.0)
    parser.add_argument("--working-set-kib", type=int, default=4096)
    parser.add_argument("--request-period-ns", type=float, default=50.0)
    parser.add_argument("--read-percent", type=int, default=80)
    parser.add_argument("--max-outstanding", type=int, default=64)
    parser.add_argument(
        "--traffic-pattern",
        choices=("uniform", "linear", "stride4k", "hotcold"),
        default="uniform",
    )

    parser.add_argument("--cxl-one-way-ns", type=float, default=50.0)
    parser.add_argument("--memory-latency-ns", type=float, default=100.0)
    parser.add_argument("--memory-bandwidth", default="32GiB/s")

    parser.add_argument("--aead-latency-ns", type=float, default=25.0)
    parser.add_argument("--aead-issue-ns", type=float, default=4.0)
    parser.add_argument("--metadata-entries", type=int, default=4096)
    parser.add_argument("--metadata-assoc", type=int, default=4)
    parser.add_argument("--metadata-hit-ns", type=float, default=4.0)
    parser.add_argument("--metadata-miss-ns", type=float, default=80.0)
    parser.add_argument("--metadata-issue-ns", type=float, default=2.0)
    parser.add_argument("--write-reservation-ns", type=float, default=0.0)
    parser.add_argument("--write-commit-ns", type=float, default=0.0)
    parser.add_argument("--write-control-issue-ns", type=float, default=2.0)
    parser.add_argument("--ratchet-every-writes", type=int, default=4096)
    parser.add_argument("--hkdf-latency-ns", type=float, default=80.0)
    return parser.parse_args()


def ns(value):
    return f"{value}ns"


args = parse_args()
if args.working_set_kib <= 0:
    raise ValueError("working set must be positive")
if not 0 <= args.read_percent <= 100:
    raise ValueError("read percentage must be in [0, 100]")
m5.core.seedRandom(args.seed)

system = System()
system.mem_mode = "timing"
system.cache_line_size = 64
system.mem_ranges = [AddrRange(f"{args.working_set_kib}KiB")]
system.voltage_domain = VoltageDomain(voltage="1.0V")
system.clk_domain = SrcClockDomain(
    clock="1GHz", voltage_domain=system.voltage_domain
)

system.tgen = PyTrafficGen(
    elastic_req=True,
    max_outstanding_reqs=args.max_outstanding,
)
system.membus = SystemXBar(
    width=64,
    frontend_latency=1,
    forward_latency=1,
    response_latency=1,
)
system.monitor = CommMonitor()
system.ebfi = EbfiController(
    mode=args.mode,
    line_size=64,
    aead_latency=ns(args.aead_latency_ns),
    aead_issue_latency=ns(args.aead_issue_ns),
    metadata_cache_entries=args.metadata_entries,
    metadata_cache_assoc=args.metadata_assoc,
    metadata_hit_latency=ns(args.metadata_hit_ns),
    metadata_miss_latency=ns(args.metadata_miss_ns),
    metadata_issue_latency=ns(args.metadata_issue_ns),
    write_reservation_latency=ns(args.write_reservation_ns),
    write_commit_latency=ns(args.write_commit_ns),
    write_control_issue_latency=ns(args.write_control_issue_ns),
    ratchet_every_writes=args.ratchet_every_writes,
    hkdf_latency=ns(args.hkdf_latency_ns),
)
system.cxl_link = Bridge(
    delay=ns(args.cxl_one_way_ns),
    req_size=128,
    resp_size=128,
    ranges=system.mem_ranges,
)
system.memory = SimpleMemory(
    range=system.mem_ranges[0],
    latency=ns(args.memory_latency_ns),
    latency_var="0ns",
    bandwidth=args.memory_bandwidth,
)

system.tgen.port = system.membus.cpu_side_ports
system.system_port = system.membus.cpu_side_ports
system.membus.mem_side_ports = system.monitor.cpu_side_port
system.monitor.mem_side_port = system.ebfi.cpu_side_port
system.ebfi.mem_side_port = system.cxl_link.cpu_side_port
system.cxl_link.mem_side_port = system.memory.port

root = Root(full_system=False, system=system)
m5.instantiate()

ticks_per_ns = 1000
warmup_ticks = int(args.warmup_us * 1000 * ticks_per_ns)
measurement_ticks = int(args.duration_us * 1000 * ticks_per_ns)
drain_ticks = int(args.drain_us * 1000 * ticks_per_ns)
period_ticks = max(1, int(args.request_period_ns * ticks_per_ns))
end_addr = args.working_set_kib * 1024


def make_traffic(duration_ticks):
    common = (
        0,
        end_addr,
        64,
        period_ticks,
        period_ticks,
        args.read_percent,
        0,
    )
    if args.traffic_pattern == "uniform":
        return [system.tgen.createRandom(duration_ticks, *common)]
    if args.traffic_pattern == "linear":
        return [system.tgen.createLinear(duration_ticks, *common)]
    if args.traffic_pattern == "stride4k":
        return [
            system.tgen.createStrided(
                duration_ticks,
                0,
                end_addr,
                0,
                64,
                64,
                4096,
                period_ticks,
                period_ticks,
                args.read_percent,
                0,
            )
        ]

    # A deterministic two-tier locality proxy: 90% of time accesses a 256 KiB
    # hot set and 10% accesses the full configured range. It is not a Zipf or
    # application trace and is reported only as an access-pattern stressor.
    hot_end = min(end_addr, 256 * 1024)
    segments = []
    remaining = duration_ticks
    for index in range(10):
        segment = remaining if index == 9 else duration_ticks // 10
        remaining -= segment
        hot_ticks = segment * 9 // 10
        cold_ticks = segment - hot_ticks
        if hot_ticks:
            segments.append(
                system.tgen.createRandom(
                    hot_ticks,
                    0,
                    hot_end,
                    64,
                    period_ticks,
                    period_ticks,
                    args.read_percent,
                    0,
                )
            )
        if cold_ticks:
            segments.append(
                system.tgen.createRandom(
                    cold_ticks,
                    0,
                    end_addr,
                    64,
                    period_ticks,
                    period_ticks,
                    args.read_percent,
                    0,
                )
            )
    return segments


config = vars(args).copy()
config["gem5_tick_ps"] = 1
with open(os.path.join(m5.options.outdir, "experiment.json"), "w") as handle:
    json.dump(config, handle, indent=2, sort_keys=True)

if warmup_ticks:
    system.tgen.start(make_traffic(warmup_ticks) + [system.tgen.createExit(0)])
    m5.simulate()
    if drain_ticks:
        m5.simulate(drain_ticks)
    m5.stats.reset()

system.tgen.start(
    make_traffic(measurement_ticks) + [system.tgen.createExit(0)]
)
exit_event = m5.simulate()
if drain_ticks:
    m5.simulate(drain_ticks)
m5.stats.dump()
print(
    f"CXL-EBFI mode={args.mode} seed={args.seed} "
    f"exit={exit_event.getCause()} tick={m5.curTick()}"
)
