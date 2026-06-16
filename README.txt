CXL-EBFI SUPPLEMENTARY ARTIFACT

DESCRIPTION
This artifact reproduces the cryptographic, protocol, formal, gem5, figure,
and RTL evidence for “CXL-EBFI: Epoch-Bound Freshness and Post-Compromise
Integrity for CXL.mem.”

PLATFORM
The Python and RTL regressions run on macOS or Linux. Rust requires a recent
stable toolchain. TLC requires Java and tla2tools.jar. gem5 v25.1.0.1 is built
from the pinned public commit listed in gem5-ebfi/gem5-version.txt.

ENVIRONMENT
- Python 3 with the cryptography package
- Rust/Cargo
- Java and TLA+ TLC 1.8.0
- gem5 build prerequisites and SCons 4.8.1
- Icarus Verilog 13.0
- Yosys 0.66
- LaTeX/IEEEtran and Python plotting dependencies for document/figure rebuilds

MAJOR COMPONENTS
- sim/: Python/Rust references, protocol model, vectors, committed summaries
- tla/: acceptance, protocol, and crash-recovery models, configurations, TLC logs
- gem5-ebfi/: timing controller, configs, scripts, results
- rtl/: synthesizable trusted-controller state machine and reports
- supplement/: supplementary manuscript source

SETUP AND RUN
See the repository README and each component README. Principal commands:

  python3 sim/cxl_ebfi_ref.py all
  python3 sim/cxl_ebfi_protocol.py all
  (cd sim && cargo test)
  (cd gem5-ebfi && scripts/run_workload_matrix.sh)
  (cd gem5-ebfi && scripts/run_write_model.sh)
  (cd gem5-ebfi && scripts/run_read_decomposition.sh)
  (cd gem5-ebfi && python3 scripts/analyze_persistence_requirements.py)
  (cd rtl && ./run.sh)

EXPECTED OUTPUT
The protocol trace reports zero accepted substitutions and all honest reads
accepted. The targeted race summary reports 11,760 safe three-writer schedules.
Correct TLC configurations complete without invariant violations; weakened
configurations produce the documented counterexamples. The RTL testbench prints
“PASS: EBFI metadata controller RTL regression,” and Yosys completes synthesis.
The gem5 access-pattern summary reports 21.70% Verified overhead for the
hot/cold stressor and approximately 50% for the three low-locality patterns.
The read decomposition reports an 8.94-11.93% AEAD increment over anchor-only
lookup and a 16.03-21.21% illustrative complete increment. The nominal write
profile reports a 6.55-12.55% increment over anchor-plus-AEAD; the slow
persistence profiles expose the documented throughput ceilings and queueing.
The analytic provisioning output reports minimum high-load depths and ideal
group sizes of 5 operations/writes at 200 ns and 21 at 1 us.
The crash model completes without violation; its weak-counter and
early-publication ablations produce the documented depth-6/depth-3 failures.

SIZE
See MANIFEST_SHA256.txt in the submission folder for SHA-256 hashes.

CONTACT
Michel Nguyen, University of the People
michel_ng@icloud.com

SCOPE
The package provides bounded desk-based evidence. It is not a production CXL
endpoint, a silicon measurement, or an unbounded cryptographic/protocol proof.
Configured persistence delays are sensitivity inputs, and the crash model is
an abstract ordering check rather than a physical journal implementation.
Anchor-only timing is a decomposition, not a secure design, and serialized
slow-persistence latency is a finite overload observation. Group commit is an
analytic recommendation, not an implemented or simulated mechanism.
