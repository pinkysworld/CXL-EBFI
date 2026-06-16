# CXL-EBFI metadata-controller RTL

This directory contains a synthesizable proof-of-implementation for the trusted
metadata controller described in the paper. It implements:

- atomic persistent-counter allocation per modeled line;
- generation-tagged, one-time reservation slots;
- reservation-to-encryption authorization;
- monotone commit with late stale-commit rejection;
- authoritative version snapshots for read-ticket construction;
- live-line and pending-reservation reference accounting; and
- retention/refcount-gated epoch erasure.

The module deliberately does **not** implement AES-GCM, HMAC, attestation, CXL
flits/IDE, TVE request tracking, SRAM macros, or the crash-consistent persistence
journal. Reservation and ticket authenticators are external cryptographic
datapaths; the RTL validates the controller state transitions that those
authenticators protect. The default 16-line/4-slot instance is a regression and
synthesis target, not a production capacity or area estimate.

## Reproduce

Requires Icarus Verilog and Yosys:

```bash
./run.sh
```

The testbench checks three same-line writers, distinct reservations, newest-first
commit, stale-commit rejection, consumed-token replay, authoritative ticket
output, pending-reservation blocking of erasure, lease expiry, and late commit
rejection. Outputs are written to `results/`. The committed
`synthesis_summary.json` records the default-instance generic cell counts and
their limitations; it is reproducibility evidence, not a production area claim.
