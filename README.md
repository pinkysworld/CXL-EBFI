# CXL-EBFI: Epoch-Bound Freshness and Post-Compromise Integrity for CXL.mem

Authenticated-encryption layer above CXL IDE that gives CXL.mem two properties IDE
does not, on its own, provide end to end: **memory-line freshness** (a read returns
the latest value, and stale/replayed lines are rejected) and **scoped
post-compromise integrity** (historical writes remain tamper-evident after their
working key is unreferenced and acknowledged erased).

The central idea is the **Epoch-Bound Memory Freshness Invariant (EBFI)**: a read is
accepted only if it authenticates, under an epoch-tied AES-256-GCM key, against the
**device-authoritative per-line version** (epoch + write counter) delivered in a
serialized read ticket, not the version echoed in the attacker-controllable
response. This rejects same-epoch rollback by construction. Independently derived
epoch keys and reference-counted, acknowledged erasure provide the scoped
post-compromise property while keeping unchanged data readable.

## Repository layout
- `cxl-ebfi-paper.tex` / `cxl-ebfi-paper.pdf` — the paper (IEEEtran). The PDF is the canonical deliverable.
- `sim/cxl_ebfi_ref.py` — cryptographic reference and sensitivity cross-check (Python, real AES-256-GCM + HKDF-SHA-256). It validates nonce/AAD/key behavior but deliberately collapses the ticket/session protocol.
- `sim/cxl_ebfi_protocol.py` — **headline security evaluation model**: separate untrusted data store, trusted metadata service, and attested TVEs. It authenticates one-time write reservations, rejects stale out-of-order commits, binds tickets to line/request/TVE/session, tracks pending and live epoch references, and runs the reported multi-seed attacks through the complete protocol.
- `sim/src/main.rs`, `sim/Cargo.toml` — Rust reference of the same construction, with a `cargo test` suite (13 tests) including concurrent-reservation and ticket-replay parity tests. Mirrors the Python model.
- `tla/CXL_EBFI_Invariant.tla` / `.cfg` — bounded TLA+ acceptance-guard model.
- `tla/CXL_EBFI_Protocol.tla` / `.cfg` — bounded reservation/commit/ticket model; non-atomic and weak-ticket configurations reproduce counterexamples. `tla/TLC_RUN.txt` and `tla/TLC_PROTOCOL_RUN.txt` record results.
- `tla/CXL_EBFI_CrashRecovery.tla` / `.cfg` — bounded one-line persistence-ordering model; weak-counter and early-publication configurations reproduce nonce-reuse and visible-before-durable counterexamples. `tla/TLC_CRASH_RUN.txt` records results.
- `figs/` — `metrics_optimistic.csv`, `metrics_verified.csv`, `summary.json` (committed results), and `generate_figures.py` (reads `summary.json`; no hardcoded values).
- `gem5-ebfi/` — gem5 timing supplement: `src/` (the EBFI memory-path controller, C++/SimObject), `configs/ebfi_cxl.py`, read and write sweep scripts, and committed result summaries. `README.md`/`SUPPLEMENT.md` document the build and every reported timing number.
- `rtl/` — synthesizable SystemVerilog proof-of-implementation for atomic reservations, encryption authorization, monotone commit, ticket snapshots, reference accounting, and guarded erasure. Includes an Icarus Verilog testbench and Yosys generic synthesis report.
- `supplement/` — IEEE-formatted supplementary material with full artifact, race, formal, gem5, workload-shape, and RTL details.

## Reproduce the results
```bash
# 1. Authoritative numbers + CSVs + summary.json (≈25 s; needs python3 `cryptography`)
python3 sim/cxl_ebfi_ref.py all --seeds 30 --hosts 3 --lines 4096 --steps 4000 --burst 0.03

# 2. Deterministic security suite (same checks as `cargo test`)
python3 sim/cxl_ebfi_ref.py selftest

# 2b. Protocol regressions plus the 30-seed end-to-end ticketed trace
python3 sim/cxl_ebfi_protocol.py all

# 2c. Targeted ticket/epoch, lease-expiry, and 11,760 three-writer schedules
python3 sim/cxl_ebfi_protocol.py races

# 3. Software crypto microbenchmark (reference path only; not the overhead basis)
python3 sim/cxl_ebfi_ref.py microbench

# 4. Figures from the committed summary.json
python3 figs/generate_figures.py
```
Rust (requires crates.io access to build):
```bash
cd sim && cargo test                  # deterministic security suite
cargo clippy --release -- -D warnings  # clean
cargo run --release -- --seeds 30 --hosts 3 --lines 4096 --steps 4000 --burst 0.03
cargo run --release -- --microbench
```
> The Python reference produces the security numbers in the paper and runs with no
> build system; the Rust crate compiles cleanly, passes its tests, and is clippy-clean.

gem5 timing supplement (requires a gem5 build; see `gem5-ebfi/README.md`):
```bash
cd gem5-ebfi
scripts/build_gem5.sh                  # build gem5 with the EBFI controller
GEM5_BIN="$(scripts/build_gem5.sh | tail -n 1)"
python3 scripts/run_matrix.py --gem5 "$GEM5_BIN" --force
scripts/run_sensitivity.sh             # AEAD-cost and metadata-miss sweeps
GEM5_BIN="$GEM5_BIN" scripts/run_workload_matrix.sh
GEM5_BIN="$GEM5_BIN" scripts/run_write_model.sh
GEM5_BIN="$GEM5_BIN" scripts/run_read_decomposition.sh
python3 scripts/analyze_persistence_requirements.py
python3 scripts/plot_results.py        # regenerate results/gem5_ebfi_overhead.pdf
```

Synthesizable controller RTL:
```bash
cd rtl
./run.sh
```

TLA+ (requires `tla2tools.jar`):
```bash
cd tla
java -cp tla2tools.jar tlc2.TLC -config CXL_EBFI_Invariant.cfg CXL_EBFI_Invariant.tla
java -cp tla2tools.jar tlc2.TLC -config CXL_EBFI_Protocol.cfg CXL_EBFI_Protocol.tla
java -cp tla2tools.jar tlc2.TLC -config CXL_EBFI_Protocol_3W.cfg CXL_EBFI_Protocol.tla
java -cp tla2tools.jar tlc2.TLC -config CXL_EBFI_CrashRecovery.cfg CXL_EBFI_CrashRecovery.tla
# Correct configurations fully enumerate with no violation.
# Protocol and crash-recovery ablations reproduce the documented counterexamples.
```

## Headline results
- **Security:** The 30-seed protocol trace accepts **0 of 1,374** stale-ciphertext/ticket substitutions, serves all **75,640** honest reads, and executes **1,433** concurrent write pairs without nonce reuse; **705** late stale commits are rejected. This is deterministic bounded evidence, not an adaptive-attacker proof.
- **gem5 timing:** Verified data/metadata-path overhead is **17.61–49.93%**; an illustrative 20 ns ticket/TVE adder makes it **27.4–59.7%**. A paired decomposition finds that configured AEAD adds **8.94–11.93%** over anchor-only lookup, and AEAD plus the illustrative crossing adds **16.03–21.21%**. Anchor-only is a cost decomposition, not a secure design. Optimistic is provisional pending recovery (**11.81%**, or **21.6%** with the same adder).
- **Modeled write timing:** A nominal **10/20 ns reservation/commit** profile adds **6.55% at 20 ns load** and **12.55% at 100 ns load** over anchor-plus-AEAD. With pipelined 200 ns or 1 us persistence, the increment becomes **116–173%** or **666–866%**. Serialized persistence saturates near its expected **2.5 or 0.5 completed writes/us** service ceiling. At the high load, queue stability requires at least **5 or 21 in-flight persistence operations**, respectively; the same ideal minimum batch sizes would amortize a serial two-barrier group commit. The batching result is analytic, not simulated.
- **Access-pattern stressors:** At 64 MiB/20 ns, Verified overhead is **49.93% uniform**, **50.04% linear**, **50.73% 4 KiB stride**, and **21.70% hot/cold** as metadata hit rate rises to 87.24%; these are synthetic locality patterns, not applications.
- **Formal:** The guard model enumerates 615,615 states; the two-writer protocol model enumerates 1,338,445 states (177,147 distinct, depth 15), and the three-writer bound enumerates 101,857 states (18,304 distinct, depth 16). The crash model enumerates 249 states (150 distinct, depth 13). Counter-unchecked, non-atomic reservation, weak-ticket, weak-counter-persistence, and early-publication configurations produce the expected counterexamples.
- **Targeted races:** A pre-advance ticket is accepted exactly once; pre-/post-encryption lease expiry rejects late actions; 11,760 three-writer schedules have zero nonce reuse, metadata regression, or accounting failure.
- **RTL:** The regression passes, and Yosys synthesizes the default 16-line/4-slot controller to 8,976 generic cells (1,779 sequential, 7,197 combinational). This excludes crypto, SRAM macros, CXL/IDE, journaling, and process timing/area.
