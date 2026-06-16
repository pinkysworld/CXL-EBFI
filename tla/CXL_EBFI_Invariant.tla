-------------------------- MODULE CXL_EBFI_Invariant --------------------------
(***************************************************************************)
(* TLA+ model of the Epoch-Bound Memory Freshness Invariant (EBFI) for     *)
(* CXL-EBFI, corrected per round-3 peer review.                            *)
(*                                                                         *)
(* This version checks a NON-TRIVIAL property: every accepted read         *)
(* response matched the device-authoritative per-line version (epoch AND   *)
(* counter) at decision time, under a usable (non-erased) epoch key.  The  *)
(* previous module checked only "e >= 0" (vacuous); this one checks counter*)
(* freshness against a trusted anchor, which is exactly what defeats the   *)
(* same-epoch replay that the prior design accepted.                       *)
(*                                                                         *)
(* TWO KEY MODELLING DEVICES                                               *)
(*  1. Trusted version anchor.  lineEpoch[a]/lineCtr[a] are the device's   *)
(*     authoritative version (root of trust).  A ReadAccept action is      *)
(*     OFFERED for any claimed (e,c) (the attacker may substitute the      *)
(*     response), but the acceptance GUARD only admits (e,c) that match the *)
(*     trusted anchor (and a usable key).  Stale/rollback (e,c) are routed  *)
(*     to ReadReject and never accepted.                                   *)
(*  2. Acceptance-time snapshots, bounded.  We keep only the most recent    *)
(*     accepted snapshot per (host,addr) -- a fixed-size function, so TLC   *)
(*     terminates with the FULL reachable state space -- and the invariant  *)
(*     is checked at every state, hence over every accept the moment it is  *)
(*     the latest.  Each snapshot freezes the decision-time anchor so later  *)
(*     Writes/AdvanceEpoch cannot retroactively falsify it.                 *)
(*                                                                         *)
(* DEMONSTRATION KNOB.  CONSTANT StrictCounter selects the guard:          *)
(*    StrictCounter = TRUE   -> correct rule (match epoch AND counter):     *)
(*                              EBFI holds, no violation (this work).        *)
(*    StrictCounter = FALSE  -> broken epoch-only rule (the prior design):  *)
(*                              TLC finds a same-epoch-rollback counter-     *)
(*                              example, proving the model checks counter    *)
(*                              freshness rather than a vacuous predicate.   *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
  Hosts,          (* set of host ids, e.g. {1,2}                       *)
  Addrs,          (* set of line addresses, e.g. {1,2}                 *)
  MaxEpoch,       (* bound on epochs for model checking, e.g. 3        *)
  MaxCtr,         (* bound on per-line counters, e.g. 2                *)
  RetentionW,     (* epoch key retention window, e.g. 2                *)
  StrictCounter   (* TRUE = correct guard; FALSE = broken epoch-only   *)

NoSnap == [none |-> TRUE]

VARIABLES
  epoch,        (* current global epoch (monotone)                     *)
  lineEpoch,    (* authoritative per-line epoch (trusted version)      *)
  lineCtr,      (* authoritative per-line counter (trusted version)    *)
  usableKeys,   (* epochs whose keys still exist (refcount/window)     *)
  lastAccept    (* [Hosts \X Addrs -> Snapshot \cup {NoSnap}]          *)

vars == << epoch, lineEpoch, lineCtr, usableKeys, lastAccept >>

Snapshots ==
  [ e: 0..MaxEpoch, c: 0..MaxCtr,
    lineEpAt: 0..MaxEpoch, lineCtrAt: 0..MaxCtr, usable: BOOLEAN ]

TypeOK ==
  /\ epoch \in 0..MaxEpoch
  /\ lineEpoch \in [Addrs -> 0..MaxEpoch]
  /\ lineCtr   \in [Addrs -> 0..MaxCtr]
  /\ usableKeys \subseteq (0..MaxEpoch)
  /\ lastAccept \in [Hosts \X Addrs -> Snapshots \cup {NoSnap}]

(* An epoch is referenced if some line's authoritative value sits in it.
   Such a key is retained even outside the window (availability). *)
Referenced(e) == \E a \in Addrs : lineEpoch[a] = e

Init ==
  /\ epoch = 1
  /\ lineEpoch = [a \in Addrs |-> 1]
  /\ lineCtr   = [a \in Addrs |-> 0]
  /\ usableKeys = {1}
  /\ lastAccept = [ha \in Hosts \X Addrs |-> NoSnap]

(* Epoch advance: retain keys for the last RetentionW epochs and for any
   still-referenced epoch; erase the rest in the abstract key-availability model. *)
AdvanceEpoch ==
  /\ epoch < MaxEpoch
  /\ epoch' = epoch + 1
  /\ usableKeys' =
       { e \in usableKeys \cup {epoch'} :
           \/ e >= epoch' - (RetentionW - 1)
           \/ Referenced(e) }
  /\ UNCHANGED << lineEpoch, lineCtr, lastAccept >>

(* A host writes a line: authoritative version advances under the current epoch.
   Counter-exhaustion rule (F7): a write is enabled only while the counter is
   below MaxCtr; at the bound the device must AdvanceEpoch (force a ratchet)
   before writing again, so the nonce counter never wraps within one epoch key. *)
Write(h, a) ==
  /\ lineCtr[a] < MaxCtr
  /\ lineEpoch' = [lineEpoch EXCEPT ![a] = epoch]
  /\ lineCtr'   = [lineCtr   EXCEPT ![a] = lineCtr[a] + 1]
  /\ UNCHANGED << epoch, usableKeys, lastAccept >>

(* The attacker substitutes a response carrying a version that ACTUALLY EXISTED
   (a real replay/rollback), i.e. an epoch no later than the current one and a
   counter no greater than the line's authoritative counter.  This makes the
   weak-rule counterexample a genuine same-epoch rollback (a smaller historical
   counter) rather than an invented future counter. *)
OfferedExisted(a, e, c) == e <= epoch /\ c <= lineCtr[a]

(* Acceptance guard.  The response claims version (e,c); the host verifies it
   against the TRUSTED authoritative version.
     StrictCounter: epoch AND counter must match     (correct, this work)
     otherwise:     epoch matches, counter UNCHECKED  (the prior epoch-only rule
                    -- a same-epoch replay authenticates under its own epoch and
                    its smaller counter was never checked, so it was accepted). *)
AcceptGuard(a, e, c) ==
  /\ e \in usableKeys
  /\ IF StrictCounter
       THEN e = lineEpoch[a] /\ c = lineCtr[a]
       ELSE e = lineEpoch[a]

Snap(a, e, c) ==
  [ e |-> e, c |-> c,
    lineEpAt |-> lineEpoch[a], lineCtrAt |-> lineCtr[a],
    usable |-> (e \in usableKeys) ]

(* ReadAccept is OFFERED for any existing (e,c) (attacker substitution); only
   guarded ones take effect and are recorded with a decision-time snapshot. *)
ReadAccept(h, a, e, c) ==
  /\ OfferedExisted(a, e, c)
  /\ AcceptGuard(a, e, c)
  /\ lastAccept' = [lastAccept EXCEPT ![<<h, a>>] = Snap(a, e, c)]
  /\ UNCHANGED << epoch, lineEpoch, lineCtr, usableKeys >>

ReadReject(h, a, e, c) ==
  /\ OfferedExisted(a, e, c)
  /\ ~ AcceptGuard(a, e, c)
  /\ UNCHANGED vars

Next ==
  \/ AdvanceEpoch
  \/ \E h \in Hosts, a \in Addrs : Write(h, a)
  \/ \E h \in Hosts, a \in Addrs, e \in 0..MaxEpoch, c \in 0..MaxCtr :
        ReadAccept(h, a, e, c) \/ ReadReject(h, a, e, c)

Spec == Init /\ [][Next]_vars

(* ---- The property actually checked ----------------------------------- *)
(* EBFI: every accepted response matched the authoritative epoch AND counter
   at its decision time, under a usable key.  This is the counter-freshness
   property; it fails for the broken epoch-only guard (same-epoch rollback). *)
EBFI ==
  \A ha \in Hosts \X Addrs :
     LET s == lastAccept[ha] IN
       (s = NoSnap) \/
         ( /\ s.e = s.lineEpAt
           /\ s.c = s.lineCtrAt
           /\ s.usable )

(* Safety clause: no accepted snapshot relied on a key that was already erased
   at decision time.  NOTE: this is a guard-structure safety property, NOT a
   model of scoped post-compromise integrity (which involves an attacker key
   capture and historical forgery -- argued cryptographically and exercised by
   the compromise experiment in the executable references, not model-checked
   here). *)
NoAcceptUnderErasedKey ==
  \A ha \in Hosts \X Addrs :
     LET s == lastAccept[ha] IN (s = NoSnap) \/ s.usable

Inv == TypeOK /\ EBFI /\ NoAcceptUnderErasedKey

=============================================================================
(* HOW TO RUN (TLC)

   Correct design (expected: no invariant violation):
     java -cp tla2tools.jar tlc2.TLC -config CXL-EBFI_Invariant.cfg \
          CXL-EBFI_Invariant.tla

   Broken epoch-only rule (expected: counterexample -- a same-epoch rollback
   is accepted), set StrictCounter = FALSE in the .cfg.  The counterexample is
   the formal analogue of the implementation bug the round-3 review found.

   The model is intentionally small-state: lastAccept is a fixed-size function
   (most recent accept per host/line), so the reachable state space is finite
   and fully enumerable -- the invariant is therefore VERIFIED (not merely
   sampled) over all reachable states for the committed bounds, unlike the
   previous accumulating-set sketch that only admitted a vacuous predicate.

   Correspondence to the implementations (sim/cxl_ebfi_ref.py, sim/src/main.rs):
     - lineEpoch/lineCtr        <-> Device.auth[a] (authoritative version, RoT)
     - AcceptGuard StrictCounter <-> Host.verify decrypting under the trusted
                                     authoritative version (rejects rollback)
     - usableKeys + AdvanceEpoch <-> reference-counted epoch_keys + ratchet
     - ReadAccept snapshot       <-> the accept decision and its decision-time
                                     trusted-version binding
   The TLA model omits concrete AEAD (MAC_OK is realised by the guard match) and
   the Gilbert-Elliott channel; those live in the executable references.        *)
