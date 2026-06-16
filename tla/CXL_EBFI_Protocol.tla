--------------------------- MODULE CXL_EBFI_Protocol ---------------------------
(***************************************************************************)
(* Bounded protocol model for CXL-EBFI write reservations and read tickets. *)
(*                                                                         *)
(* The write side models two or more writers that may reserve and encrypt   *)
(* concurrently. AtomicReservation allocates at reservation time; the       *)
(* ablation allocates from the committed counter and can reuse a nonce. A   *)
(* commit succeeds only when its counter is newer than authCtr, so a late   *)
(* older reservation is rejected and cannot roll authoritative metadata    *)
(* backward.                                                               *)
(*                                                                         *)
(* The read side models outstanding request identifiers and tickets bound   *)
(* to an owner/session and line. StrictTicketBinding checks both bindings   *)
(* and consumes the request and ticket once. The ablation omits those checks*)
(* and admits a cross-line or cross-owner ticket acceptance.                *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
  Writers,
  Lines,
  Rids,
  MaxCtr,
  AtomicReservation,
  StrictTicketBinding

NoLine == 0
WritePhases == {"idle", "reserved", "encrypted", "done", "stale"}

VARIABLES
  allocCtr,
  authCtr,
  phase,
  reservedCtr,
  usedNonces,
  nonceReuse,
  outstanding,
  ticketLine,
  badTicketAccept

vars == << allocCtr, authCtr, phase, reservedCtr, usedNonces, nonceReuse,
           outstanding, ticketLine, badTicketAccept >>

TypeOK ==
  /\ allocCtr \in 0..MaxCtr
  /\ authCtr \in 0..MaxCtr
  /\ phase \in [Writers -> WritePhases]
  /\ reservedCtr \in [Writers -> 0..MaxCtr]
  /\ usedNonces \subseteq (1..MaxCtr)
  /\ nonceReuse \in BOOLEAN
  /\ outstanding \in [Writers -> [Rids -> Lines \cup {NoLine}]]
  /\ ticketLine \in [Writers \X Rids -> Lines \cup {NoLine}]
  /\ badTicketAccept \in BOOLEAN

Init ==
  /\ allocCtr = 0
  /\ authCtr = 0
  /\ phase = [w \in Writers |-> "idle"]
  /\ reservedCtr = [w \in Writers |-> 0]
  /\ usedNonces = {}
  /\ nonceReuse = FALSE
  /\ outstanding = [w \in Writers |-> [r \in Rids |-> NoLine]]
  /\ ticketLine = [wr \in Writers \X Rids |-> NoLine]
  /\ badTicketAccept = FALSE

Reserve(w) ==
  /\ phase[w] = "idle"
  /\ (IF AtomicReservation THEN allocCtr ELSE authCtr) < MaxCtr
  /\ LET c == (IF AtomicReservation THEN allocCtr ELSE authCtr) + 1 IN
       /\ reservedCtr' = [reservedCtr EXCEPT ![w] = c]
       /\ allocCtr' = IF AtomicReservation THEN c ELSE allocCtr
  /\ phase' = [phase EXCEPT ![w] = "reserved"]
  /\ UNCHANGED << authCtr, usedNonces, nonceReuse, outstanding,
                  ticketLine, badTicketAccept >>

Encrypt(w) ==
  /\ phase[w] = "reserved"
  /\ nonceReuse' = nonceReuse \/ (reservedCtr[w] \in usedNonces)
  /\ usedNonces' = usedNonces \cup {reservedCtr[w]}
  /\ phase' = [phase EXCEPT ![w] = "encrypted"]
  /\ UNCHANGED << allocCtr, authCtr, reservedCtr, outstanding,
                  ticketLine, badTicketAccept >>

Commit(w) ==
  /\ phase[w] = "encrypted"
  /\ IF reservedCtr[w] > authCtr
       THEN /\ authCtr' = reservedCtr[w]
            /\ phase' = [phase EXCEPT ![w] = "done"]
       ELSE /\ authCtr' = authCtr
            /\ phase' = [phase EXCEPT ![w] = "stale"]
  /\ allocCtr' =
       IF AtomicReservation \/ reservedCtr[w] <= allocCtr
         THEN allocCtr
         ELSE reservedCtr[w]
  /\ UNCHANGED << reservedCtr, usedNonces, nonceReuse, outstanding,
                  ticketLine, badTicketAccept >>

BeginRead(w, r, line) ==
  /\ outstanding[w][r] = NoLine
  /\ outstanding' = [outstanding EXCEPT ![w][r] = line]
  /\ UNCHANGED << allocCtr, authCtr, phase, reservedCtr, usedNonces,
                  nonceReuse, ticketLine, badTicketAccept >>

IssueTicket(owner, r, line) ==
  /\ ticketLine[<<owner, r>>] = NoLine
  /\ ticketLine' = [ticketLine EXCEPT ![<<owner, r>>] = line]
  /\ UNCHANGED << allocCtr, authCtr, phase, reservedCtr, usedNonces,
                  nonceReuse, outstanding, badTicketAccept >>

TicketGuard(owner, verifier, r, line) ==
  /\ outstanding[verifier][r] = line
  /\ ticketLine[<<owner, r>>] # NoLine
  /\ IF StrictTicketBinding
       THEN owner = verifier /\ ticketLine[<<owner, r>>] = line
       ELSE TRUE

VerifyTicket(owner, verifier, r, line) ==
  /\ TicketGuard(owner, verifier, r, line)
  /\ badTicketAccept' =
       (badTicketAccept
        \/ (owner # verifier)
        \/ (ticketLine[<<owner, r>>] # line))
  /\ outstanding' = [outstanding EXCEPT ![verifier][r] = NoLine]
  /\ ticketLine' = [ticketLine EXCEPT ![<<owner, r>>] = NoLine]
  /\ UNCHANGED << allocCtr, authCtr, phase, reservedCtr, usedNonces,
                  nonceReuse >>

Next ==
  \/ \E w \in Writers : Reserve(w) \/ Encrypt(w) \/ Commit(w)
  \/ \E w \in Writers, r \in Rids, line \in Lines : BeginRead(w, r, line)
  \/ \E owner \in Writers, r \in Rids, line \in Lines :
       IssueTicket(owner, r, line)
  \/ \E owner \in Writers, verifier \in Writers, r \in Rids, line \in Lines :
       VerifyTicket(owner, verifier, r, line)

Spec == Init /\ [][Next]_vars

ReservationUnique ==
  \A w1, w2 \in Writers :
    (w1 # w2
     /\ phase[w1] # "idle"
     /\ phase[w2] # "idle")
      => reservedCtr[w1] # reservedCtr[w2]

NoNonceReuse == ~ nonceReuse
NoBadTicketAccept == ~ badTicketAccept
CommittedWithinAllocation == authCtr <= allocCtr

Inv ==
  /\ TypeOK
  /\ ReservationUnique
  /\ NoNonceReuse
  /\ NoBadTicketAccept
  /\ CommittedWithinAllocation

=============================================================================
