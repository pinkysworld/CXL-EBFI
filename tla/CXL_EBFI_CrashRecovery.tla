----------------------- MODULE CXL_EBFI_CrashRecovery -----------------------
(***************************************************************************)
(* Bounded crash-recovery model for one line's failure-atomic write path.   *)
(* Persistent state consists of the counter high-watermark, authenticated   *)
(* intent, durable ciphertext set, redo record, and visible descriptor.     *)
(* A crash discards only the volatile execution mode. Recovery never        *)
(* reclaims a reserved counter and publishes a redo record only when its    *)
(* ciphertext is durable.                                                   *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS MaxCtr, PersistHighWatermark, RequireDurableBeforePublish

NoCtr == 0
Modes == {"normal", "recovering"}

VARIABLES
  highWatermark,
  intentCtr,
  durableCiphertexts,
  redoCtr,
  descriptorCtr,
  usedNonces,
  nonceReuse,
  encryptedThisOp,
  mode

vars == << highWatermark, intentCtr, durableCiphertexts, redoCtr,
           descriptorCtr, usedNonces, nonceReuse, encryptedThisOp, mode >>

TypeOK ==
  /\ highWatermark \in 0..MaxCtr
  /\ intentCtr \in 0..MaxCtr
  /\ durableCiphertexts \subseteq (1..MaxCtr)
  /\ redoCtr \in 0..MaxCtr
  /\ descriptorCtr \in 0..MaxCtr
  /\ usedNonces \subseteq (1..MaxCtr)
  /\ nonceReuse \in BOOLEAN
  /\ encryptedThisOp \in BOOLEAN
  /\ mode \in Modes

Init ==
  /\ highWatermark = 0
  /\ intentCtr = NoCtr
  /\ durableCiphertexts = {}
  /\ redoCtr = NoCtr
  /\ descriptorCtr = NoCtr
  /\ usedNonces = {}
  /\ nonceReuse = FALSE
  /\ encryptedThisOp = FALSE
  /\ mode = "normal"

Reserve ==
  /\ mode = "normal"
  /\ intentCtr = NoCtr
  /\ highWatermark < MaxCtr
  /\ intentCtr' = highWatermark + 1
  /\ highWatermark' =
       IF PersistHighWatermark THEN highWatermark + 1 ELSE highWatermark
  /\ encryptedThisOp' = FALSE
  /\ UNCHANGED << durableCiphertexts, redoCtr, descriptorCtr, usedNonces,
                  nonceReuse, mode >>

Encrypt ==
  /\ mode = "normal"
  /\ intentCtr # NoCtr
  /\ ~encryptedThisOp
  /\ durableCiphertexts' = durableCiphertexts \cup {intentCtr}
  /\ nonceReuse' = (nonceReuse \/ (intentCtr \in usedNonces))
  /\ usedNonces' = usedNonces \cup {intentCtr}
  /\ encryptedThisOp' = TRUE
  /\ UNCHANGED << highWatermark, intentCtr, redoCtr, descriptorCtr, mode >>

PrepareRedo ==
  /\ mode = "normal"
  /\ intentCtr # NoCtr
  /\ encryptedThisOp
  /\ intentCtr \in durableCiphertexts
  /\ redoCtr = NoCtr
  /\ redoCtr' = intentCtr
  /\ UNCHANGED << highWatermark, intentCtr, durableCiphertexts,
                  descriptorCtr, usedNonces, nonceReuse, encryptedThisOp,
                  mode >>

Publish ==
  /\ mode = "normal"
  /\ intentCtr # NoCtr
  /\ IF RequireDurableBeforePublish
       THEN redoCtr = intentCtr /\ intentCtr \in durableCiphertexts
       ELSE TRUE
  /\ descriptorCtr' = intentCtr
  /\ UNCHANGED << highWatermark, intentCtr, durableCiphertexts, redoCtr,
                  usedNonces, nonceReuse, encryptedThisOp, mode >>

Cleanup ==
  /\ mode = "normal"
  /\ intentCtr # NoCtr
  /\ descriptorCtr = intentCtr
  /\ intentCtr' = NoCtr
  /\ redoCtr' = NoCtr
  /\ encryptedThisOp' = FALSE
  /\ UNCHANGED << highWatermark, durableCiphertexts, descriptorCtr,
                  usedNonces, nonceReuse, mode >>

Abort ==
  /\ mode = "normal"
  /\ intentCtr # NoCtr
  /\ descriptorCtr # intentCtr
  /\ intentCtr' = NoCtr
  /\ redoCtr' = NoCtr
  /\ encryptedThisOp' = FALSE
  /\ UNCHANGED << highWatermark, durableCiphertexts, descriptorCtr,
                  usedNonces, nonceReuse, mode >>

Crash ==
  /\ mode = "normal"
  /\ mode' = "recovering"
  /\ encryptedThisOp' = FALSE
  /\ UNCHANGED << highWatermark, intentCtr, durableCiphertexts, redoCtr,
                  descriptorCtr, usedNonces, nonceReuse >>

Recover ==
  /\ mode = "recovering"
  /\ descriptorCtr' =
       IF redoCtr # NoCtr /\ redoCtr \in durableCiphertexts
         THEN redoCtr
         ELSE descriptorCtr
  /\ intentCtr' = NoCtr
  /\ redoCtr' = NoCtr
  /\ encryptedThisOp' = FALSE
  /\ mode' = "normal"
  /\ UNCHANGED << highWatermark, durableCiphertexts, usedNonces, nonceReuse >>

Next ==
  \/ Reserve
  \/ Encrypt
  \/ PrepareRedo
  \/ Publish
  \/ Cleanup
  \/ Abort
  \/ Crash
  \/ Recover

Spec == Init /\ [][Next]_vars

VisibleVersionIsDurable ==
  descriptorCtr = NoCtr \/ descriptorCtr \in durableCiphertexts

NoNonceReuse == ~nonceReuse
PublishedWithinHighWatermark == descriptorCtr <= highWatermark
RedoReferencesDurableData ==
  redoCtr = NoCtr \/ redoCtr \in durableCiphertexts

Inv ==
  /\ TypeOK
  /\ VisibleVersionIsDurable
  /\ NoNonceReuse
  /\ PublishedWithinHighWatermark
  /\ RedoReferencesDurableData

CounterPersistenceInv ==
  /\ TypeOK
  /\ NoNonceReuse

DurablePublicationInv ==
  /\ TypeOK
  /\ VisibleVersionIsDurable

=============================================================================
