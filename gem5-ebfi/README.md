# CXL-EBFI gem5 timing model

This artifact adds an out-of-tree EBFI memory-path controller to gem5
v25.1.0.1. It measures how AEAD pipelining, trusted-version caching,
authenticated metadata misses, queueing, ratchets, and configured write
reservation/commit delays affect a CXL-like disaggregated-memory path.

The question it answers is narrow: given explicit component latencies and issue
rates, what end-to-end latency, contention, cache behavior, and Optimistic
verification window do we see under offered load? AES-GCM and HKDF circuit
latencies are configuration parameters here, not measured silicon.

## Mode behavior

- `baseline`: identical CXL-like link and memory, with no EBFI delay.
- `optimistic`: authenticated version lookup begins with the memory request;
  the response is released after AEAD verification. The model records checks
  that finish after release and the resulting speculative-use window.
- `verified`: the authoritative version lookup is serialized after the data
  response, then AEAD verification runs before release.

Writes run through the pipelined AEAD engine, update the trusted-version
cache, and periodically incur an HKDF ratchet. Optional write-control delays
place persistent reservation before encryption and persistent commit after
the memory response.

## Default topology

```text
PyTrafficGen -> SystemXBar -> CommMonitor -> EbfiController
             -> CXL Bridge -> SimpleMemory
```

The defaults are a 64-byte line, 50 ns one-way CXL bridge delay, 100 ns memory
latency, 32 GiB/s memory bandwidth, a 4,096-entry four-way trusted-version
cache, 4 ns metadata hits, 80 ns authenticated misses, a 25 ns AEAD latency
with 4 ns issue interval, and an 80 ns HKDF latency every 4,096 writes.

## Reproduce

The build script pins both the gem5 release and commit:

```bash
./scripts/build_gem5.sh
./scripts/run_quick.sh
```

For the paper matrix:

```bash
GEM5_BIN="$(./scripts/build_gem5.sh | tail -n 1)"
python3 scripts/run_matrix.py --gem5 "$GEM5_BIN" --force
GEM5_BIN="$GEM5_BIN" ./scripts/run_sensitivity.sh
GEM5_BIN="$GEM5_BIN" ./scripts/run_workload_matrix.sh
GEM5_BIN="$GEM5_BIN" ./scripts/run_write_model.sh
GEM5_BIN="$GEM5_BIN" ./scripts/run_read_decomposition.sh
python3 scripts/analyze_persistence_requirements.py
python3 scripts/plot_results.py
```

Raw per-seed data, 95% confidence intervals, logs, complete commands, and the
configuration for every run are written below `results/`.

The access-pattern matrix fixes the working set at 64 MiB and the request
period at 20 ns, then compares uniform, linear, 4 KiB-stride, and deterministic
hot/cold traffic over five paired seeds. It is a locality stress test, not an
application-workload study.

Important sweep parameters can be passed directly to `run_matrix.py`, including
`--aead-latency-ns`, `--aead-issue-ns`, `--metadata-entries`,
`--metadata-hit-ns`, `--metadata-miss-ns`, and `--metadata-issue-ns`.
The write sweep uses 5/10 ns through 1 us reservation/commit profiles,
including pipelined and serialized slow-persistence stress points, and writes
summaries to `results/write-path/`. The read-decomposition sweep compares an
insecure baseline, anchor-only lookup, and anchor-plus-AEAD under paired
traffic. It writes summaries to `results/read-decomposition/`. Anchor-only is
included solely to isolate timing cost; it does not authenticate returned data.
The persistence-analysis script derives the shared-root issue interval,
minimum in-flight depth, and ideal minimum group-commit size from the measured
offered write rates. It is an analytic provisioning calculation rather than a
batching simulation.

## Interpretation limits

This is a timing-focused architectural model, not a complete CXL protocol
implementation, a cryptographic functional model, or an RTL implementation.
`Bridge` represents CXL-like transport delay and buffering; `SimpleMemory`
represents device memory. The model does not simulate flits, IDE, retries,
coherence, power, area, speculative rollback machinery, or attacks. Security
correctness remains covered by the paper's Python/Rust/TLA+ artifacts.

So the right way to read these results is as workload- and cache-dependent
timing evidence: they expose queueing and Optimistic late-verification windows
and show sensitivity to the hardware calibration. The trusted-version cache is
logically part of the device/fabric metadata service. The model does not
implement tickets, TVE attestation/provisioning, or distributed key zeroization,
and the serialized slow-persistence runs are finite overload stress tests, not
steady-state latency bounds. The configured AES/HKDF and persistence latencies
are inputs, not numbers gem5 discovered. Group commit only works if it keeps
durable-before-publish ordering; a descriptor becoming visible before its
ciphertext and redo record are durable falls outside the checked invariant.
