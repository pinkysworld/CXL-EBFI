# Supplement: gem5 timing evaluation of CXL-EBFI

## Purpose

The original evaluation charged every Optimistic read a fixed AEAD cost and
every Verified read an additional fixed version-fetch cost. That arithmetic did
not model a metadata protocol, cache residency, overlap, or queueing. This
supplement replaces the fixed version-fetch charge with an implemented gem5
timing path.

The model is intentionally architectural rather than RTL. It measures
end-to-end effects after assigning component latencies and issue rates; it does
not discover AES-GCM or HKDF circuit latency. Those values remain calibrated
inputs and are swept.

## Simulator and topology

- gem5 v25.1.0.1, commit
  `c8222cc67a399bfc01e8658dd14b30d5bfd634f9`
- Out-of-tree `EbfiController` derived from gem5 `MemDelay`
- 1 GHz controller clock and 64-byte lines
- `PyTrafficGen -> SystemXBar -> CommMonitor -> EbfiController -> Bridge -> SimpleMemory`
- 50 ns bridge delay in each direction
- 100 ns device-memory latency and 32 GiB/s bandwidth
- 4,096-entry, four-way trusted-version cache
- 4 ns metadata hit, 80 ns authenticated miss, 2 ns issue interval
- 25 ns AEAD latency, 4 ns AEAD issue interval
- 80 ns HKDF ratchet every 4,096 writes

`baseline`, `optimistic`, and `verified` use the same seeded traffic and
CXL-like memory path. Optimistic starts the authenticated metadata lookup with
the request and releases data after AEAD verification. Verified serializes the
metadata lookup and AEAD verification after the data response. The controller
records cache hits, misses, queueing, ratchets, and any Optimistic verification
that completes after release.

## Method

Each point uses five seeds, a 100 us warm-up, a 5 us drain, a 500 us measured
interval, and another 5 us drain. Traffic is 80% reads and 20% writes with at
most 64 outstanding requests. The matrix varies:

- Working set: 256 KiB, 4 MiB, and 64 MiB
- Request period: 20 ns and 100 ns

The warm-up and measurement generators are separate. Statistics are reset only
after warm-up requests drain, while the trusted-version cache remains warm.
Overhead is paired per seed against the identical baseline configuration.
Reported intervals are 95% confidence intervals across seeds.

## Main results

The baseline read latency is 205.0 ns at every tested point.

| Mode | Working set | Period | Read latency | Overhead | Metadata hit rate |
|---|---:|---:|---:|---:|---:|
| Optimistic | 256 KiB | 20 ns | 229.21 ns | 11.81% | 95.14% |
| Optimistic | 256 KiB | 100 ns | 229.21 ns | 11.81% | 60.25% |
| Optimistic | 4 MiB | 20 ns | 229.21 ns | 11.81% | 11.93% |
| Optimistic | 4 MiB | 100 ns | 229.21 ns | 11.81% | 22.96% |
| Optimistic | 64 MiB | 20 ns | 229.21 ns | 11.81% | 6.03% |
| Optimistic | 64 MiB | 100 ns | 229.21 ns | 11.81% | 20.05% |
| Verified | 256 KiB | 20 ns | 241.10 ns | 17.61% | 95.14% |
| Verified | 256 KiB | 100 ns | 263.21 ns | 28.39% | 60.25% |
| Verified | 4 MiB | 20 ns | 305.86 ns | 49.20% | 11.93% |
| Verified | 4 MiB | 100 ns | 291.55 ns | 42.22% | 22.96% |
| Verified | 64 MiB | 20 ns | 307.36 ns | 49.93% | 6.03% |
| Verified | 64 MiB | 100 ns | 293.77 ns | 43.30% | 20.05% |

The largest 95% confidence interval is 0.27 ns for latency and 0.13 percentage
points for overhead. Optimistic metadata checks all complete before release
under the nominal 80 ns miss path because the lookup overlaps the 205 ns remote
memory path. Verified performance is governed by trusted-version cache
residency, which the previous fixed 12 ns charge concealed.

## Read-path cost decomposition

A paired sweep retains the same serialized trusted-version lookup but disables
AEAD in an `anchor_only` profile. This is a timing decomposition, not a secure
EBFI alternative: without AEAD, returned data is not bound to the authoritative
version.

| Working set | Period | Anchor-only | Anchor + AEAD | AEAD increment | Illustrative EBFI increment |
|---|---:|---:|---:|---:|---:|
| 256 KiB | 20 ns | 215.41 ns | 241.10 ns | 11.93% | 21.21% |
| 256 KiB | 100 ns | 238.21 ns | 263.21 ns | 10.50% | 18.89% |
| 4 MiB | 20 ns | 280.43 ns | 305.86 ns | 9.07% | 16.20% |
| 4 MiB | 100 ns | 266.55 ns | 291.55 ns | 9.38% | 16.88% |
| 64 MiB | 20 ns | 282.14 ns | 307.36 ns | 8.94% | 16.03% |
| 64 MiB | 100 ns | 268.77 ns | 293.77 ns | 9.30% | 16.74% |

The final column adds the illustrative, unimplemented 20 ns ticket/TVE crossing
to anchor-plus-AEAD. It isolates a total 16.03-21.21% EBFI read-path increment
over anchor lookup, but remains a configured path estimate.

## Sensitivity

At a 4 MiB working set and 20 ns request period:

| Sweep | Optimistic overhead | Verified overhead |
|---|---:|---:|
| AEAD 10 ns | 4.49% | 41.90% |
| AEAD 25 ns | 11.81% | 49.22% |
| AEAD 50 ns | 24.00% | 61.41% |
| Metadata miss 40 ns | 11.81% | 29.92% |
| Metadata miss 80 ns | 11.81% | 49.22% |
| Metadata miss 160 ns | 11.81% | 88.19% |
| Metadata miss 320 ns | 11.81% | 166.23% |

Metadata misses up to 160 ns remain hidden behind the Optimistic remote-data
path. At a stressed 320 ns metadata miss latency, 88.20% of Optimistic reads
release before verification completes, with a mean 91.80 ns late-verification
window. This is not a modeled rollback/recovery penalty; it is the measured
window that a concrete squash or containment mechanism would have to cover.

## Write reservation and commit sensitivity

The dedicated write sweep uses the 64 MiB uniform-random workload, 80/20
read/write traffic, five paired seeds, and request periods of 20 ns and 100 ns.
The `anchor_aead` profile performs Verified-mode encryption with zero
reservation/commit delay. EBFI profiles configure persistent reservation before
AEAD and persistent commit after the memory response.

| Profile | Reservation / commit | Period | Write latency | Increment vs anchor |
|---|---:|---:|---:|---:|
| Anchor + AEAD | 0 / 0 ns | 20 ns | 291.50 ns | -- |
| Low | 5 / 10 ns | 20 ns | 300.53 ns | 3.10% |
| Nominal | 10 / 20 ns | 20 ns | 310.60 ns | 6.55% |
| High | 20 / 40 ns | 20 ns | 330.80 ns | 13.48% |
| Anchor + AEAD | 0 / 0 ns | 100 ns | 231.00 ns | -- |
| Low | 5 / 10 ns | 100 ns | 245.00 ns | 6.06% |
| Nominal | 10 / 20 ns | 100 ns | 260.00 ns | 12.55% |
| High | 20 / 40 ns | 100 ns | 290.00 ns | 25.54% |

At 20 ns, the nominal latency CI is +/-0.29 ns and its anchor-relative
increment CI is +/-0.015 percentage points. These values are configured
storage-delay sensitivities, not measured persistent media, journal, or flush
latency.

### Slow-persistence stress test

The extended sweep configures 200 ns and 1 us for both reservation and commit.
Pipelined profiles keep a 2 ns issue interval. Serialized profiles permit one
persistence operation per configured delay, giving ideal service ceilings of
2.5 and 0.5 writes/us because each write requires two persistence operations.

| Organization | Reservation / commit | Period | Completed-write latency | Completed writes/us |
|---|---:|---:|---:|---:|
| Pipelined | 200 / 200 ns | 20 ns | 630.53 ns | 10.299 |
| Pipelined | 200 / 200 ns | 100 ns | 630.34 ns | 2.049 |
| Pipelined | 1 / 1 us | 20 ns | 2,232.61 ns | 9.166 |
| Pipelined | 1 / 1 us | 100 ns | 2,230.34 ns | 2.049 |
| Serialized | 200 / 200 ns | 20 ns | 8,792.26 ns | 2.524 |
| Serialized | 200 / 200 ns | 100 ns | 1,480.20 ns | 2.049 |
| Serialized | 1 / 1 us | 20 ns | 44,682.24 ns | 0.503 |
| Serialized | 1 / 1 us | 100 ns | 44,910.35 ns | 0.502 |

Pipelined 200 ns persistence adds 116-173% over anchor-plus-AEAD; pipelined
1 us adds 666-866%. Under the 20 ns offered load, serialized persistence
saturates and queueing dominates. These are finite 500 us overload
observations with a 5 us drain, not steady-state latency bounds. Low-latency
or sufficiently parallel durable metadata is therefore a deployment
requirement.

### Provisioning and group commit

The observed write rates are 10.299 and 2.049 writes/us. A shared root that
performs reservation and commit persistence needs an issue interval no larger
than `1000 / (2 * write_rate)` ns: 48.5 ns and 244.0 ns. The minimum pipeline
depth is `ceil(persistence_latency / issue_interval)`.

| Period | Persistence latency | Minimum in-flight operations | Ideal minimum group size |
|---|---:|---:|---:|
| 20 ns | 200 ns | 5 | 5 |
| 20 ns | 1 us | 21 | 21 |
| 100 ns | 200 ns | 1 | 1 |
| 100 ns | 1 us | 5 | 5 |

Pipeline depth prevents queue collapse but does not reduce individual
persistence latency. For a serial barrier, grouping `B` writes gives ideal
barrier-limited capacity `B / (2 * persistence_latency)`. A safe group commit
persists every reservation high-watermark and intent before returning any
included capability, and persists ciphertext and redo records before swinging
the corresponding descriptors. Only cleanup after publication may be
asynchronous. This mitigation is analytic and unimplemented; it introduces
batch waiting, conflicts, and a larger recovery set.

## Access-pattern stressors

At a 64 MiB working set and 20 ns request period, five paired seeds produce:

| Pattern | Baseline | Optimistic overhead | Verified overhead | Metadata hit rate |
|---|---:|---:|---:|---:|
| Uniform | 205.00 ns | 11.81% | 49.93% | 6.03% |
| Linear | 205.00 ns | 11.81% | 50.04% | 1.90% |
| 4 KiB stride | 205.00 ns | 11.81% | 50.73% | 0.00% |
| Hot/cold | 205.00 ns | 11.81% | 21.70% | 87.24% |

The hot/cold generator spends 90% of simulated time in a 256 KiB hot set and
10% across the full range. These patterns are deterministic synthetic locality
stressors, not application traces or a Zipf distribution. They confirm that
Verified timing is driven by metadata-cache locality, while the nominal
Optimistic path overlaps the lookup.

## What the paper can claim

The artifact supports these claims:

1. The Optimistic and Verified paths are distinct timing state machines rather
   than labels attached to a constant-cost formula.
2. The fixed 12 ns Verified version-fetch assumption is not robust. A finite
   trusted-version cache makes Verified overhead workload dependent.
3. Under the nominal CXL-like path, Optimistic hides an 80 ns metadata miss,
   while Verified pays it serially.
4. Slow metadata paths create a measurable speculative-use window in
   Optimistic mode.
5. Configured write reservation and commit delay can be isolated against an
   anchor-plus-AEAD path at both tested offered loads.
6. AEAD adds 8.94-11.93% over anchor-only lookup in the tested read paths; the
   illustrative complete EBFI path adds 16.03-21.21%.
7. A slow serialized persistence root can become the write-throughput
   bottleneck even when the data and crypto paths are pipelined.
8. At the high offered load, a shared 200 ns or 1 us root needs at least 5 or
   21 in-flight operations; ideal group commit needs the same minimum batch
   sizes, while preserving durable-before-publish.

It does not support claims of measured AES hardware latency, full CXL flit
fidelity, application-level slowdown, area/power, or implemented speculative
rollback. Those require RTL synthesis, a detailed CXL model, full-system
workloads, or hardware-in-the-loop evaluation.

## Reproduction

```bash
./scripts/build_gem5.sh
GEM5_BIN="$(./scripts/build_gem5.sh | tail -n 1)"
python3 scripts/run_matrix.py --gem5 "$GEM5_BIN" --force
GEM5_BIN="$GEM5_BIN" ./scripts/run_sensitivity.sh
GEM5_BIN="$GEM5_BIN" ./scripts/run_workload_matrix.sh
GEM5_BIN="$GEM5_BIN" ./scripts/run_write_model.sh
GEM5_BIN="$GEM5_BIN" ./scripts/run_read_decomposition.sh
python3 scripts/analyze_persistence_requirements.py
/usr/local/bin/python3.11 scripts/plot_results.py
```

Per-run commands, logs, configuration JSON, raw CSV, summaries, and figures are
under `results/`.
