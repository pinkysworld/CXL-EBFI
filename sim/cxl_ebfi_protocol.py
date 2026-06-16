#!/usr/bin/env python3
"""
CXL-EBFI protocol model with separate trusted metadata, TVEs, and untrusted data.

The model exercises the mechanisms abstracted by cxl_ebfi_ref.py:

* authenticated, one-time write reservations bound to a TVE session and writer;
* unique counters under concurrent same-line writers and stale-commit rejection;
* read tickets bound to line, request, TVE, and boot/session identity;
* live-line and pending-reservation accounting for acknowledged epoch erasure;
* targeted epoch/ticket, lease-expiry, and three-writer race schedules;
* multi-seed attacker traces that pass through the complete ticketed protocol.

Run:
  python3 sim/cxl_ebfi_protocol.py selftest
  python3 sim/cxl_ebfi_protocol.py races
  python3 sim/cxl_ebfi_protocol.py trace --seeds 30 --hosts 3 --lines 4096 --steps 4000
  python3 sim/cxl_ebfi_protocol.py all
"""

import argparse
import hashlib
import hmac
import itertools
import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import cxl_ebfi_ref as ref

LINE_SIZE = ref.LINE_SIZE


@dataclass(frozen=True)
class Version:
    line: int
    epoch: int
    ctr: int
    writer: int


@dataclass(frozen=True)
class Reservation:
    line: int
    epoch: int
    ctr: int
    writer: int
    tve_id: int
    session: bytes
    token: bytes
    mac: bytes


@dataclass(frozen=True)
class Ticket:
    line: int
    epoch: int
    ctr: int
    writer: int
    rid: bytes
    tve_id: int
    session: bytes
    mac: bytes


@dataclass(frozen=True)
class StoredCT:
    ct: bytes
    epoch: int
    ctr: int
    writer: int


class DataStore:
    """Attacker-controlled bulk ciphertext store."""

    def __init__(self):
        self.lines: Dict[int, StoredCT] = {}

    def put(self, line: int, value: StoredCT):
        self.lines[line] = value

    def get(self, line: int) -> Optional[StoredCT]:
        return self.lines.get(line)


class MetadataService:
    """Trusted serialization, metadata, reservation, ticket, and erasure service."""

    def __init__(self, seed: int = 1, atomic_reservation: bool = True):
        rng = ref._Rng(seed ^ 0xD3F1CE)
        self._root = rng.randbytes(32)
        self._ticket_mac_key = rng.randbytes(32)
        self._reservation_mac_key = rng.randbytes(32)
        self._rng = rng
        self.atomic_reservation = atomic_reservation
        self.current_epoch = 1
        self.auth: Dict[int, Version] = {}
        self._alloc_ctr: Dict[int, int] = {}
        self.epoch_writes: Dict[Tuple[int, int], int] = {}
        self.refcount: Dict[int, int] = {1: 0}
        self.pending_refcount: Dict[int, int] = {1: 0}
        self._pending: Dict[bytes, Tuple[Reservation, str]] = {}
        self._consumed_tokens: set[bytes] = set()
        self.tves: Dict[int, "TVE"] = {}
        self._next_tve_id = 1
        self._device_handles: Dict[int, bytes] = {1: self.epoch_key(1)}
        self.erased: set[int] = set()
        self.revoke_attempts: Dict[int, int] = {}

    def epoch_key(self, epoch: int) -> bytes:
        return ref.hkdf_sha256(self._root, epoch)

    def register_tve(self, tve: "TVE") -> Tuple[int, bytes]:
        tve_id = self._next_tve_id
        self._next_tve_id += 1
        session = self._rng.randbytes(16)
        self.tves[tve_id] = tve
        return tve_id, session

    def _active_tve(self, tve_id: int, session: bytes) -> Optional["TVE"]:
        tve = self.tves.get(tve_id)
        if tve is None or tve.session != session:
            return None
        return tve

    @staticmethod
    def _fields(*parts: bytes) -> bytes:
        return b"|".join(parts)

    def _reservation_mac(self, line: int, epoch: int, ctr: int, writer: int,
                         tve_id: int, session: bytes, token: bytes) -> bytes:
        msg = self._fields(
            line.to_bytes(8, "little"),
            epoch.to_bytes(8, "little"),
            ctr.to_bytes(8, "little"),
            bytes([writer]),
            tve_id.to_bytes(8, "little"),
            session,
            token,
        )
        return hmac.new(self._reservation_mac_key, msg, hashlib.sha256).digest()

    def _reservation_ok(self, reservation: Reservation) -> bool:
        expected = self._reservation_mac(
            reservation.line,
            reservation.epoch,
            reservation.ctr,
            reservation.writer,
            reservation.tve_id,
            reservation.session,
            reservation.token,
        )
        return hmac.compare_digest(reservation.mac, expected)

    def reserve_write(self, tve: "TVE", line: int) -> Reservation:
        """Issue an authenticated one-time reservation for this TVE and writer."""
        if self._active_tve(tve.tve_id, tve.session) is not tve:
            raise ValueError("inactive or mismatched TVE session")
        if self.epoch_writes.get((self.current_epoch, line), 0) + 1 >= ref.CTR_LIMIT:
            self.ratchet()

        allocated = self._alloc_ctr.get(line, 0)
        ctr = allocated + 1
        if self.atomic_reservation:
            self._alloc_ctr[line] = ctr

        token = self._rng.randbytes(16)
        mac = self._reservation_mac(
            line, self.current_epoch, ctr, tve.writer, tve.tve_id, tve.session, token
        )
        reservation = Reservation(
            line, self.current_epoch, ctr, tve.writer, tve.tve_id, tve.session, token, mac
        )
        self._pending[token] = (reservation, "reserved")
        self.pending_refcount[reservation.epoch] = \
            self.pending_refcount.get(reservation.epoch, 0) + 1
        self.epoch_writes[(reservation.epoch, line)] = \
            self.epoch_writes.get((reservation.epoch, line), 0) + 1
        return reservation

    def authorize_encryption(self, tve: "TVE", reservation: Reservation) -> bool:
        """Consume the reservation's encryption right exactly once."""
        pending = self._pending.get(reservation.token)
        if pending != (reservation, "reserved"):
            return False
        if not self._reservation_ok(reservation):
            return False
        if self._active_tve(reservation.tve_id, reservation.session) is not tve:
            return False
        if reservation.writer != tve.writer:
            return False
        if reservation.epoch in self.erased or reservation.epoch not in tve._handles:
            return False
        self._pending[reservation.token] = (reservation, "encrypted")
        return True

    def _retire_pending(self, reservation: Reservation):
        self._pending.pop(reservation.token, None)
        self._consumed_tokens.add(reservation.token)
        count = self.pending_refcount.get(reservation.epoch, 0)
        if count <= 0:
            raise AssertionError("pending reservation refcount underflow")
        self.pending_refcount[reservation.epoch] = count - 1

    def abort_write(self, reservation: Reservation) -> bool:
        pending = self._pending.get(reservation.token)
        if pending is None or pending[0] != reservation:
            return False
        self._retire_pending(reservation)
        self._try_retire_epochs()
        return True

    def expire_write(self, reservation: Reservation) -> bool:
        """Authenticate a lease-expiry decision and retire its pending reference.

        Wall-clock lease validation is outside this executable model. This method
        models the atomic state transition after the trusted service has decided
        that a reservation's authenticated lease expired.
        """
        return self.abort_write(reservation)

    def commit_write(self, store: DataStore, reservation: Reservation, ct: bytes) -> bool:
        """Atomically publish ciphertext and metadata, or reject a stale commit.

        Successful commit is the write linearization point. A reservation with a
        counter no greater than the current committed counter is consumed and
        rejected, so a late older writer cannot roll metadata or data backward.
        """
        pending = self._pending.get(reservation.token)
        if pending != (reservation, "encrypted") or not self._reservation_ok(reservation):
            return False
        if reservation.epoch in self.erased:
            self._retire_pending(reservation)
            return False

        current = self.auth.get(reservation.line)
        if current is not None and reservation.ctr <= current.ctr:
            self._retire_pending(reservation)
            self._try_retire_epochs()
            return False

        staged = StoredCT(
            ct, reservation.epoch, reservation.ctr, reservation.writer
        )
        if current is not None:
            old_count = self.refcount.get(current.epoch, 0)
            if old_count <= 0:
                raise AssertionError("live-line refcount underflow")
            self.refcount[current.epoch] = old_count - 1

        # This method is the model's trusted atomic persistence transaction.
        store.put(reservation.line, staged)
        self.auth[reservation.line] = Version(
            reservation.line,
            reservation.epoch,
            reservation.ctr,
            reservation.writer,
        )
        self.refcount[reservation.epoch] = self.refcount.get(reservation.epoch, 0) + 1
        if not self.atomic_reservation:
            self._alloc_ctr[reservation.line] = max(
                self._alloc_ctr.get(reservation.line, 0), reservation.ctr
            )
        self._retire_pending(reservation)
        self._try_retire_epochs()
        return True

    def _ticket_mac(self, line: int, epoch: int, ctr: int, writer: int,
                    rid: bytes, tve_id: int, session: bytes) -> bytes:
        msg = self._fields(
            line.to_bytes(8, "little"),
            epoch.to_bytes(8, "little"),
            ctr.to_bytes(8, "little"),
            bytes([writer]),
            rid,
            tve_id.to_bytes(8, "little"),
            session,
        )
        return hmac.new(self._ticket_mac_key, msg, hashlib.sha256).digest()

    def read_ticketed(self, line: int, rid: bytes, tve: "TVE") -> Ticket:
        if self._active_tve(tve.tve_id, tve.session) is not tve:
            raise ValueError("inactive or mismatched TVE session")
        version = self.auth[line]
        mac = self._ticket_mac(
            line, version.epoch, version.ctr, version.writer,
            rid, tve.tve_id, tve.session
        )
        return Ticket(
            line, version.epoch, version.ctr, version.writer,
            rid, tve.tve_id, tve.session, mac
        )

    def ticket_ok(self, ticket: Ticket) -> bool:
        expected = self._ticket_mac(
            ticket.line, ticket.epoch, ticket.ctr, ticket.writer,
            ticket.rid, ticket.tve_id, ticket.session
        )
        return hmac.compare_digest(ticket.mac, expected)

    def ratchet(self):
        self.current_epoch += 1
        self.refcount.setdefault(self.current_epoch, 0)
        self.pending_refcount.setdefault(self.current_epoch, 0)
        self._device_handles[self.current_epoch] = self.epoch_key(self.current_epoch)
        for tve in self.tves.values():
            tve.provision(self.current_epoch)
        self._try_retire_epochs()

    def _eligible_for_revoke(self, epoch: int) -> bool:
        cutoff = self.current_epoch - ref.RETENTION_W + 1
        return (
            epoch < cutoff
            and self.refcount.get(epoch, 0) == 0
            and self.pending_refcount.get(epoch, 0) == 0
            and epoch not in self.erased
        )

    def _try_retire_epochs(self):
        for epoch in sorted(self._device_handles):
            if self._eligible_for_revoke(epoch):
                self.revoke(epoch)

    def revoke(self, epoch: int) -> bool:
        """Classify an epoch erased only after every active TVE acknowledges."""
        if not self._eligible_for_revoke(epoch):
            return False
        self.revoke_attempts[epoch] = self.revoke_attempts.get(epoch, 0) + 1
        if not all(tve.revoke(epoch) for tve in self.tves.values()):
            return False
        self._device_handles.pop(epoch, None)
        self.erased.add(epoch)
        return True

    def accounting_ok(self) -> bool:
        live = {epoch: 0 for epoch in self.refcount}
        for version in self.auth.values():
            live[version.epoch] = live.get(version.epoch, 0) + 1
        pending = {epoch: 0 for epoch in self.pending_refcount}
        for reservation, _ in self._pending.values():
            pending[reservation.epoch] = pending.get(reservation.epoch, 0) + 1
        return (
            all(value >= 0 for value in self.refcount.values())
            and all(value >= 0 for value in self.pending_refcount.values())
            and all(self.refcount.get(epoch, 0) == count for epoch, count in live.items())
            and all(
                self.pending_refcount.get(epoch, 0) == count
                for epoch, count in pending.items()
            )
        )


class TVE:
    """Trusted verifier with a writer identity and a boot/session namespace."""

    def __init__(self, meta: MetadataService, endpoint_writer: int):
        self.meta = meta
        self.writer = endpoint_writer
        self._handles: Dict[int, Optional[bytes]] = {}
        self._outstanding: Dict[bytes, int] = {}
        self._rid_counter = 0
        self.tve_id, self.session = meta.register_tve(self)
        for epoch in meta._device_handles:
            self.provision(epoch)

    def provision(self, epoch: int):
        self._handles[epoch] = self.meta.epoch_key(epoch)

    def revoke(self, epoch: int) -> bool:
        self._handles[epoch] = None
        return True

    def begin_read(self, line: int) -> bytes:
        self._rid_counter += 1
        rid = self.session + self._rid_counter.to_bytes(8, "little")
        self._outstanding[rid] = line
        return rid

    def cancel_read(self, rid: bytes):
        self._outstanding.pop(rid, None)

    def verify_ticket(self, ticket: Ticket, line: int) -> Optional[Version]:
        if not self.meta.ticket_ok(ticket):
            return None
        if ticket.line != line:
            return None
        if ticket.tve_id != self.tve_id or ticket.session != self.session:
            return None
        if self._outstanding.get(ticket.rid) != line:
            return None
        del self._outstanding[ticket.rid]
        return Version(ticket.line, ticket.epoch, ticket.ctr, ticket.writer)

    def enc(self, reservation: Reservation, data: bytes) -> bytes:
        if not self.meta.authorize_encryption(self, reservation):
            raise ValueError("invalid, replayed, or cross-writer reservation")
        key = self._handles.get(reservation.epoch)
        if key is None:
            raise ValueError("epoch handle unavailable")
        return AESGCM(key).encrypt(
            ref.make_nonce(
                reservation.line,
                reservation.epoch,
                reservation.ctr,
                reservation.writer,
            ),
            data,
            ref.make_aad(
                reservation.line, reservation.epoch, reservation.writer
            ),
        )

    def dec(self, version: Version, ct: bytes) -> Optional[bytes]:
        key = self._handles.get(version.epoch)
        if key is None:
            return None
        try:
            return AESGCM(key).decrypt(
                ref.make_nonce(
                    version.line, version.epoch, version.ctr, version.writer
                ),
                ct,
                ref.make_aad(version.line, version.epoch, version.writer),
            )
        except Exception:
            return None


def protocol_write(
    tve: TVE, meta: MetadataService, store: DataStore, line: int, data: bytes
) -> Tuple[Reservation, bool]:
    reservation = meta.reserve_write(tve, line)
    ct = tve.enc(reservation, data)
    return reservation, meta.commit_write(store, reservation, ct)


def protocol_read(
    tve: TVE,
    meta: MetadataService,
    store: DataStore,
    line: int,
    attacker_response: Optional[StoredCT] = None,
    attacker_ticket: Optional[Ticket] = None,
) -> Tuple[str, Optional[bytes]]:
    rid = tve.begin_read(line)
    ticket = attacker_ticket or meta.read_ticketed(line, rid, tve)
    response = attacker_response or store.get(line)
    version = tve.verify_ticket(ticket, line)
    if version is None:
        tve.cancel_read(rid)
        return "reject", None
    if response is None:
        return "reject", None
    plaintext = tve.dec(version, response.ct)
    return ("accept", plaintext) if plaintext is not None else ("reject", None)


def concurrent_write_interleavings(atomic: bool) -> Tuple[bool, int, int]:
    """Enumerate all six order-preserving two-writer reserve/commit schedules."""
    reuse = 0
    stale_rejects = 0
    safe = True
    for order in set(itertools.permutations(["r1", "c1", "r2", "c2"])):
        if order.index("r1") > order.index("c1"):
            continue
        if order.index("r2") > order.index("c2"):
            continue
        meta = MetadataService(seed=5, atomic_reservation=atomic)
        store = DataStore()
        t0, t1, t2 = TVE(meta, 0), TVE(meta, 1), TVE(meta, 2)
        _, committed = protocol_write(t0, meta, store, 7, b"0" * LINE_SIZE)
        assert committed
        reservations: Dict[str, Reservation] = {}
        ciphertexts: Dict[str, bytes] = {}
        nonces: List[bytes] = []
        auth_history = [meta.auth[7].ctr]

        for step in order:
            if step == "r1":
                reservation = meta.reserve_write(t1, 7)
                reservations["r1"] = reservation
                ciphertexts["r1"] = t1.enc(reservation, b"A" * LINE_SIZE)
                nonces.append(
                    ref.make_nonce(
                        reservation.line,
                        reservation.epoch,
                        reservation.ctr,
                        reservation.writer,
                    )
                )
            elif step == "r2":
                reservation = meta.reserve_write(t2, 7)
                reservations["r2"] = reservation
                ciphertexts["r2"] = t2.enc(reservation, b"B" * LINE_SIZE)
                nonces.append(
                    ref.make_nonce(
                        reservation.line,
                        reservation.epoch,
                        reservation.ctr,
                        reservation.writer,
                    )
                )
            else:
                key = "r1" if step == "c1" else "r2"
                if not meta.commit_write(store, reservations[key], ciphertexts[key]):
                    stale_rejects += 1
                auth_history.append(meta.auth[7].ctr)

        if len(set(nonces)) != len(nonces):
            safe = False
            reuse += 1
        if auth_history != sorted(auth_history):
            safe = False
        if not meta.accounting_ok():
            safe = False
    return safe, reuse, stale_rejects


def _interleave(sequences: Dict[str, Tuple[str, ...]]):
    """Yield all order-preserving interleavings without duplicate schedules."""
    names = tuple(sequences)
    positions = {name: 0 for name in names}
    schedule: List[Tuple[str, str]] = []

    def visit():
        if all(positions[name] == len(sequences[name]) for name in names):
            yield tuple(schedule)
            return
        for name in names:
            index = positions[name]
            if index == len(sequences[name]):
                continue
            action = sequences[name][index]
            positions[name] += 1
            schedule.append((name, action))
            yield from visit()
            schedule.pop()
            positions[name] -= 1

    yield from visit()


@dataclass
class TargetedRaceSummary:
    ticket_before_epoch_advance_accepts: int = 0
    consumed_ticket_replays_rejected: int = 0
    reservation_expiry_scenarios: int = 0
    late_actions_after_expiry_rejected: int = 0
    three_writer_schedules: int = 0
    three_writer_nonce_reuses: int = 0
    three_writer_monotonicity_failures: int = 0
    three_writer_accounting_failures: int = 0
    stale_commits_rejected: int = 0


def _ticket_epoch_race(summary: TargetedRaceSummary):
    meta = MetadataService(seed=101)
    store = DataStore()
    tve = TVE(meta, 1)
    _, committed = protocol_write(tve, meta, store, 9, b"old" * 21 + b"x")
    assert committed
    old_response = store.get(9)
    rid = tve.begin_read(9)
    ticket = meta.read_ticketed(9, rid, tve)

    # Epoch advance alone does not invalidate an already linearized read. The
    # old key remains live because the line still references it.
    meta.ratchet()
    version = tve.verify_ticket(ticket, 9)
    if version is not None and old_response is not None:
        if tve.dec(version, old_response.ct) is not None:
            summary.ticket_before_epoch_advance_accepts += 1

    # The request and ticket were consumed exactly once.
    if tve.verify_ticket(ticket, 9) is None:
        summary.consumed_ticket_replays_rejected += 1


def _reservation_expiry_races(summary: TargetedRaceSummary):
    for expire_after_encrypt in (False, True):
        meta = MetadataService(seed=201 + int(expire_after_encrypt))
        store = DataStore()
        tve = TVE(meta, 1)
        _, committed = protocol_write(tve, meta, store, 1, b"a" * LINE_SIZE)
        assert committed
        held = meta.reserve_write(tve, 2)
        held_ct = None
        if expire_after_encrypt:
            held_ct = tve.enc(held, b"b" * LINE_SIZE)

        # Move the only live line out of epoch 1, then advance far enough that
        # the held reservation is the sole reason epoch 1 cannot retire.
        meta.ratchet()
        _, committed = protocol_write(tve, meta, store, 1, b"c" * LINE_SIZE)
        assert committed
        for _ in range(ref.RETENTION_W + 1):
            meta.ratchet()
        assert 1 not in meta.erased
        assert meta.expire_write(held)
        assert 1 in meta.erased
        summary.reservation_expiry_scenarios += 1

        if expire_after_encrypt:
            if not meta.commit_write(store, held, held_ct):
                summary.late_actions_after_expiry_rejected += 1
        else:
            try:
                tve.enc(held, b"late" * 16)
                rejected = False
            except ValueError:
                rejected = True
            if rejected:
                summary.late_actions_after_expiry_rejected += 1


def _run_three_writer_schedule(
    schedule: Tuple[Tuple[str, str], ...],
    dispositions: Dict[str, str],
    seed: int,
    summary: TargetedRaceSummary,
):
    meta = MetadataService(seed=seed)
    store = DataStore()
    tves = {name: TVE(meta, writer + 1)
            for writer, name in enumerate(sorted(dispositions))}
    initial = TVE(meta, 7)
    _, committed = protocol_write(initial, meta, store, 5, b"0" * LINE_SIZE)
    assert committed
    reservations: Dict[str, Reservation] = {}
    ciphertexts: Dict[str, bytes] = {}
    nonces: List[bytes] = []
    auth_history = [meta.auth[5].ctr]

    for name, action in schedule:
        tve = tves[name]
        if action == "reserve":
            reservations[name] = meta.reserve_write(tve, 5)
        elif action == "encrypt":
            reservation = reservations[name]
            ciphertexts[name] = tve.enc(
                reservation, bytes([tve.writer]) * LINE_SIZE
            )
            nonces.append(ref.make_nonce(
                reservation.line,
                reservation.epoch,
                reservation.ctr,
                reservation.writer,
            ))
        elif action == "commit":
            if not meta.commit_write(
                store, reservations[name], ciphertexts[name]
            ):
                summary.stale_commits_rejected += 1
            auth_history.append(meta.auth[5].ctr)
        elif action == "abort":
            assert meta.abort_write(reservations[name])
        elif action == "expire":
            assert meta.expire_write(reservations[name])
        else:
            raise AssertionError(f"unknown action {action}")

    summary.three_writer_schedules += 1
    if len(set(nonces)) != len(nonces):
        summary.three_writer_nonce_reuses += 1
    if auth_history != sorted(auth_history):
        summary.three_writer_monotonicity_failures += 1
    if not meta.accounting_ok():
        summary.three_writer_accounting_failures += 1


def run_targeted_races() -> TargetedRaceSummary:
    """Enumerate targeted lifecycle and three-writer race schedules."""
    summary = TargetedRaceSummary()
    _ticket_epoch_race(summary)
    _reservation_expiry_races(summary)

    # All three writers commit: 1,680 order-preserving schedules.
    all_commit = {
        name: ("reserve", "encrypt", "commit") for name in ("a", "b", "c")
    }
    dispositions = {name: "commit" for name in all_commit}
    for index, schedule in enumerate(_interleave(all_commit)):
        _run_three_writer_schedule(schedule, dispositions, 3000 + index, summary)

    # One commit, one abort, and one lease expiry. Rotate the roles to cover all
    # six assignments; each assignment has 1,680 schedules.
    names = ("a", "b", "c")
    for role_index, roles in enumerate(itertools.permutations(
        ("commit", "abort", "expire")
    )):
        dispositions = dict(zip(names, roles))
        sequences = {
            name: ("reserve", "encrypt", disposition)
            for name, disposition in dispositions.items()
        }
        for index, schedule in enumerate(_interleave(sequences)):
            _run_three_writer_schedule(
                schedule,
                dispositions,
                10000 + role_index * 2000 + index,
                summary,
            )
    return summary


@dataclass
class TraceSummary:
    seeds: int = 0
    steps_per_seed: int = 0
    honest_reads: int = 0
    honest_reads_accepted: int = 0
    attacks: int = 0
    attacks_accepted: int = 0
    stale_ciphertext_attacks: int = 0
    consumed_ticket_replays: int = 0
    cross_line_ticket_attacks: int = 0
    forged_ticket_attacks: int = 0
    concurrent_write_pairs: int = 0
    stale_commits_rejected: int = 0
    nonce_reuses: int = 0


def run_protocol_trace(
    seeds: int = 30, hosts: int = 3, lines: int = 4096, steps: int = 4000
) -> TraceSummary:
    """Run labeled attacks through the ticketed protocol, including concurrency."""
    total = TraceSummary(seeds=seeds, steps_per_seed=steps)
    for seed in range(42, 42 + seeds):
        rng = ref._Rng(seed ^ 0xA77AC)
        meta = MetadataService(seed=seed)
        store = DataStore()
        tves = [TVE(meta, writer) for writer in range(hosts)]
        history: Dict[int, List[StoredCT]] = {}

        def ensure_line(line: int, tve: TVE):
            if line not in meta.auth:
                _, committed = protocol_write(
                    tve, meta, store, line, rng.randbytes(LINE_SIZE)
                )
                assert committed

        for step in range(steps):
            line = rng.randint(0, lines)
            tve = tves[rng.randint(0, hosts)]
            ensure_line(line, tve)

            if step and step % 521 == 0:
                meta.ratchet()

            draw = rng.random()
            if draw < 0.012 and hosts >= 2:
                t1 = tves[rng.randint(0, hosts)]
                t2 = tves[(t1.writer + 1) % hosts]
                old = store.get(line)
                if old is not None:
                    history.setdefault(line, []).append(old)
                    history[line] = history[line][-4:]
                r1 = meta.reserve_write(t1, line)
                r2 = meta.reserve_write(t2, line)
                c1 = t1.enc(r1, rng.randbytes(LINE_SIZE))
                c2 = t2.enc(r2, rng.randbytes(LINE_SIZE))
                nonces = {
                    ref.make_nonce(r1.line, r1.epoch, r1.ctr, r1.writer),
                    ref.make_nonce(r2.line, r2.epoch, r2.ctr, r2.writer),
                }
                if len(nonces) != 2:
                    total.nonce_reuses += 1
                commits = [(r1, c1), (r2, c2)]
                if rng.random() < 0.5:
                    commits.reverse()
                for reservation, ct in commits:
                    if not meta.commit_write(store, reservation, ct):
                        total.stale_commits_rejected += 1
                total.concurrent_write_pairs += 1
                continue

            if draw < 0.36:
                old = store.get(line)
                if old is not None:
                    history.setdefault(line, []).append(old)
                    history[line] = history[line][-4:]
                _, committed = protocol_write(
                    tve, meta, store, line, rng.randbytes(LINE_SIZE)
                )
                assert committed
                continue

            attack_kind = rng.randint(0, 4) if rng.random() < 0.018 else -1
            if attack_kind >= 0:
                total.attacks += 1
                if attack_kind in (0, 3) and not history.get(line):
                    old = store.get(line)
                    history.setdefault(line, []).append(old)
                    _, committed = protocol_write(
                        tve, meta, store, line, rng.randbytes(LINE_SIZE)
                    )
                    assert committed

                if attack_kind == 0:
                    status, _ = protocol_read(
                        tve, meta, store, line,
                        attacker_response=history[line][0]
                    )
                    total.stale_ciphertext_attacks += 1
                elif attack_kind == 1:
                    rid = tve.begin_read(line)
                    old_ticket = meta.read_ticketed(line, rid, tve)
                    current = store.get(line)
                    assert tve.verify_ticket(old_ticket, line) is not None
                    status, _ = protocol_read(
                        tve, meta, store, line,
                        attacker_response=current,
                        attacker_ticket=old_ticket,
                    )
                    total.consumed_ticket_replays += 1
                elif attack_kind == 2:
                    other = (line + 1) % lines
                    ensure_line(other, tve)
                    other_rid = tve.begin_read(other)
                    wrong_line_ticket = meta.read_ticketed(other, other_rid, tve)
                    status, _ = protocol_read(
                        tve, meta, store, line,
                        attacker_ticket=wrong_line_ticket,
                    )
                    tve.cancel_read(other_rid)
                    total.cross_line_ticket_attacks += 1
                else:
                    rid = tve.begin_read(line)
                    good = meta.read_ticketed(line, rid, tve)
                    forged = Ticket(
                        good.line, good.epoch, good.ctr + 1, good.writer,
                        good.rid, good.tve_id, good.session, good.mac,
                    )
                    version = tve.verify_ticket(forged, line)
                    tve.cancel_read(rid)
                    status = "accept" if version is not None else "reject"
                    total.forged_ticket_attacks += 1
                if status == "accept":
                    total.attacks_accepted += 1
            else:
                status, _ = protocol_read(tve, meta, store, line)
                total.honest_reads += 1
                if status == "accept":
                    total.honest_reads_accepted += 1

            if not meta.accounting_ok():
                raise AssertionError(f"reference accounting failed at seed {seed}, step {step}")

    return total


def selftest() -> int:
    failures: List[str] = []

    def check(name: str, condition: bool):
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        if not condition:
            failures.append(name)

    meta = MetadataService(seed=1)
    store = DataStore()
    tve = TVE(meta, endpoint_writer=3)
    _, committed = protocol_write(
        tve, meta, store, 42, b"hello".ljust(LINE_SIZE, b"\x00")
    )
    status, plaintext = protocol_read(tve, meta, store, 42)
    check("honest ticketed read accepted", committed and status == "accept"
          and plaintext.startswith(b"hello"))
    check("first live line is reference-counted", meta.refcount[1] == 1)

    tve_b = TVE(meta, endpoint_writer=9)
    status, plaintext = protocol_read(tve_b, meta, store, 42)
    check("cross-TVE read accepted", status == "accept" and plaintext.startswith(b"hello"))

    atomic_safe, atomic_reuse, stale_rejects = concurrent_write_interleavings(True)
    buggy_safe, buggy_reuse, _ = concurrent_write_interleavings(False)
    check("all atomic two-writer interleavings preserve nonce and commit monotonicity",
          atomic_safe and atomic_reuse == 0 and stale_rejects > 0)
    check("non-atomic reservation reproduces nonce reuse",
          not buggy_safe and buggy_reuse > 0)

    r_old = meta.reserve_write(tve, 42)
    c_old = tve.enc(r_old, b"old-late".ljust(LINE_SIZE, b"\x00"))
    r_new = meta.reserve_write(tve, 42)
    c_new = tve.enc(r_new, b"new-first".ljust(LINE_SIZE, b"\x00"))
    new_ok = meta.commit_write(store, r_new, c_new)
    old_ok = meta.commit_write(store, r_old, c_old)
    check("late older commit is rejected without metadata rollback",
          new_ok and not old_ok and meta.auth[42].ctr == r_new.ctr)

    cross_writer = meta.reserve_write(tve, 42)
    try:
        tve_b.enc(cross_writer, b"x" * LINE_SIZE)
        cross_writer_rejected = False
    except ValueError:
        cross_writer_rejected = True
    meta.abort_write(cross_writer)
    check("cross-writer reservation use rejected", cross_writer_rejected)

    one_time = meta.reserve_write(tve, 42)
    tve.enc(one_time, b"once".ljust(LINE_SIZE, b"\x00"))
    try:
        tve.enc(one_time, b"twice".ljust(LINE_SIZE, b"\x00"))
        replay_rejected = False
    except ValueError:
        replay_rejected = True
    meta.abort_write(one_time)
    check("write reservation encryption right is one-time", replay_rejected)

    rid_old = tve.begin_read(42)
    ticket_old = meta.read_ticketed(42, rid_old, tve)
    current = store.get(42)
    assert tve.verify_ticket(ticket_old, 42) is not None
    status, _ = protocol_read(
        tve, meta, store, 42,
        attacker_response=current,
        attacker_ticket=ticket_old,
    )
    check("replayed consumed ticket rejected", status == "reject")

    _, committed = protocol_write(tve, meta, store, 43, b"other".ljust(LINE_SIZE, b"\x00"))
    assert committed
    rid_cross = tve.begin_read(43)
    cross_line = meta.read_ticketed(43, rid_cross, tve)
    check("cross-line ticket rejected", tve.verify_ticket(cross_line, 42) is None)
    tve.cancel_read(rid_cross)

    rid_relay = tve.begin_read(42)
    ticket_for_a = meta.read_ticketed(42, rid_relay, tve)
    check("cross-TVE ticket relay rejected", tve_b.verify_ticket(ticket_for_a, 42) is None)
    tve.cancel_read(rid_relay)

    old_ct = store.get(42)
    _, committed = protocol_write(
        tve, meta, store, 42, b"v2".ljust(LINE_SIZE, b"\x00")
    )
    assert committed
    status, _ = protocol_read(tve, meta, store, 42, attacker_response=old_ct)
    check("current ticket with stale ciphertext rejected", status == "reject")

    meta2 = MetadataService(seed=2)
    store2 = DataStore()
    tve2 = TVE(meta2, endpoint_writer=1)
    _, committed = protocol_write(tve2, meta2, store2, 5, b"\x00" * LINE_SIZE)
    assert committed
    aborted = meta2.reserve_write(tve2, 5)
    meta2.abort_write(aborted)
    next_reservation = meta2.reserve_write(tve2, 5)
    check("aborted write skips its counter", next_reservation.ctr == aborted.ctr + 1)
    meta2.abort_write(next_reservation)

    races = run_targeted_races()
    check("ticket issued before epoch advance remains valid once",
          races.ticket_before_epoch_advance_accepts == 1
          and races.consumed_ticket_replays_rejected == 1)
    check("reservation expiry blocks late encryption and commit",
          races.reservation_expiry_scenarios == 2
          and races.late_actions_after_expiry_rejected == 2)
    check("three-writer commit/abort/expiry schedules are safe",
          races.three_writer_schedules == 11760
          and races.three_writer_nonce_reuses == 0
          and races.three_writer_monotonicity_failures == 0
          and races.three_writer_accounting_failures == 0)

    meta3 = MetadataService(seed=3)
    store3 = DataStore()
    t_a, t_b = TVE(meta3, 1), TVE(meta3, 2)
    _, committed = protocol_write(t_a, meta3, store3, 1, b"x" * LINE_SIZE)
    assert committed
    held = meta3.reserve_write(t_a, 2)
    meta3.ratchet()
    _, committed = protocol_write(t_a, meta3, store3, 1, b"y" * LINE_SIZE)
    assert committed
    t_b.revoke = lambda epoch: False
    for _ in range(ref.RETENTION_W + 2):
        meta3.ratchet()
    check("pending reservation prevents epoch revocation",
          meta3.revoke_attempts.get(1, 0) == 0 and 1 not in meta3.erased)
    meta3.abort_write(held)
    check("revocation attempted after pending reservation resolves",
          meta3.revoke_attempts.get(1, 0) > 0 and 1 not in meta3.erased)
    t_b.revoke = lambda epoch: True
    meta3.revoke(1)
    check("epoch erased only after every active TVE acknowledges", 1 in meta3.erased)
    check("live and pending reference accounting remains exact", meta3.accounting_ok())

    print(f"\nprotocol selftest: {'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 0 if not failures else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "cmd", choices=["selftest", "races", "trace", "all"],
        nargs="?", default="all"
    )
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--hosts", type=int, default=3)
    parser.add_argument("--lines", type=int, default=4096)
    parser.add_argument("--steps", type=int, default=4000)
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(__file__), "protocol_summary.json"),
    )
    parser.add_argument(
        "--races-output",
        default=os.path.join(
            os.path.dirname(__file__), "protocol_races_summary.json"
        ),
    )
    args = parser.parse_args()

    if args.cmd in ("selftest", "all"):
        rc = selftest()
        if rc:
            return rc
    if args.cmd in ("races", "all"):
        races = run_targeted_races()
        with open(args.races_output, "w", encoding="utf-8") as handle:
            json.dump(asdict(races), handle, indent=2)
        print("\ntargeted protocol races:")
        print(json.dumps(asdict(races), indent=2))
        if (
            races.ticket_before_epoch_advance_accepts != 1
            or races.consumed_ticket_replays_rejected != 1
            or races.reservation_expiry_scenarios != 2
            or races.late_actions_after_expiry_rejected != 2
            or races.three_writer_nonce_reuses
            or races.three_writer_monotonicity_failures
            or races.three_writer_accounting_failures
        ):
            return 1
    if args.cmd in ("trace", "all"):
        summary = run_protocol_trace(args.seeds, args.hosts, args.lines, args.steps)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(asdict(summary), handle, indent=2)
        print("\nprotocol trace:")
        print(json.dumps(asdict(summary), indent=2))
        if (
            summary.attacks_accepted
            or summary.nonce_reuses
            or summary.honest_reads != summary.honest_reads_accepted
        ):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
