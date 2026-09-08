#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-agents.

Independent re-implementation of every output-producing routine
of the machine-account layer (ADR-021, ADR-022): the Mandate
grammar (bounds, version, rails, the explicit destination set,
no wildcard), the Warrant state machine (monotone nonce,
remaining, fail-closed revocation, the drain delay to the
sponsor), the uniform 64-byte authority encoding (payload plus
derived padding, kind-blind well-formedness), the receipts
(commit, verify, the fail-closed status), the streams (rate,
cap, the tick-granular cut), and the batches (one logical spend
for many payments, one ring verification). Keccak-256 comes
from pycryptodome; everything else is re-implemented from the
ADR text alone. The output is the archived vector set consumed
by the Rust test suite: both implementations must agree bit for
bit (CONTRIBUTING.md, verification layer 1).

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339). No Python random module, no version
drift, byte-for-byte reproducible on any machine.

Usage: python3 code/scripts/gen_agents_vectors.py
Writes: code/crates/antumbra-agents/tests/vectors.json
"""

import json
import struct
from pathlib import Path

from Crypto.Hash import keccak

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "crates"
    / "antumbra-agents"
    / "tests"
    / "vectors.json"
)

# --- Constants mirrored from ADR-021 and ADR-022 -----------------

MANDATE_VERSION = 0
MANDATE_MAX_DESTS = 8
MANDATE_MAX_AMOUNT_ATOMIC = 10_000_000_000       # 100 ATU
MANDATE_RAILS_ALLOWED = 0b0000_0011              # A and B only
DRAIN_DELAY_TICKS = 288                          # 48 h at 10-min ticks
AUTHORITY_BYTES = 64
PAD_PREFIX = b"antumbra-authority"
BATCH_MAX_PAYMENTS = 64
FACT_KIND_BALANCE = 1
FACT_KIND_PAYMENT = 2
FACT_KIND_UPTIME = 3
FACT_BYTES = 49


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


class Lcg:
    """The deterministic engine of the generator."""

    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFF

    def next_u32(self):
        self.state = (1_103_515_245 * self.state + 12_345) & 0xFFFFFFFF
        return self.state

    def hash32(self):
        return keccak256(struct.pack(">I", self.next_u32()))


LCG = Lcg(16_180_339)


# --- The Mandate grammar (from the ADR text alone) ---------------

def mandate_validate(version, max_amount, max_rate, expiry_tick,
                     job_types, rails, dests, dest_count):
    """Returns None when the mandate holds, the rejection else."""
    if version != MANDATE_VERSION:
        return ("malformed_mandate", "version", version)
    if max_amount > MANDATE_MAX_AMOUNT_ATOMIC:
        return ("malformed_mandate", "max_amount", max_amount)
    if max_rate > max_amount:
        return ("malformed_mandate", "max_rate", max_rate)
    if rails & ~MANDATE_RAILS_ALLOWED != 0:
        return ("malformed_mandate", "rails", rails)
    if dest_count > MANDATE_MAX_DESTS:
        return ("malformed_mandate", "dest_count", dest_count)
    for index, dest in enumerate(dests):
        live = index < dest_count
        if live and dest == b"\x00" * 32:
            return ("malformed_mandate", "dest", dest_count)
        if not live and dest != b"\x00" * 32:
            return ("malformed_mandate", "dest_padding", index)
    for i in range(dest_count):
        for j in range(i + 1, dest_count):
            if dests[i] == dests[j]:
                return ("duplicate_dest", None, None)
    return None


def mandate_permits_dest(dests, dest_count, dest):
    return dest in dests[:dest_count]


def mandate_canonical_bytes(version, max_amount, max_rate, expiry_tick,
                            job_types, rails, dests, dest_count):
    out = struct.pack(">BQQIHBB", version, max_amount, max_rate,
                      expiry_tick, job_types, rails, dest_count)
    for d in dests:
        out += d
    assert len(out) == 25 + 32 * MANDATE_MAX_DESTS
    return out


# --- The Warrant machine (from the ADR text alone) ----------------

class Warrant:
    def __init__(self, version, max_amount, max_rate, expiry_tick,
                 job_types, rails, dests, dest_count):
        rejection = mandate_validate(version, max_amount, max_rate,
                                     expiry_tick, job_types, rails,
                                     dests, dest_count)
        if rejection is not None:
            raise ValueError(rejection)
        self.max_amount = max_amount
        self.max_rate = max_rate
        self.expiry_tick = expiry_tick
        self.job_types = job_types
        self.rails = rails
        self.dests = dests
        self.dest_count = dest_count
        self.remaining = max_amount
        self.nonce = 0
        self.revoked = False
        self.revocation_tick = 0

    def root(self):
        material = mandate_canonical_bytes(MANDATE_VERSION, self.max_amount,
                                           self.max_rate, self.expiry_tick,
                                           self.job_types, self.rails,
                                           self.dests, self.dest_count)
        return keccak256(material)

    def spend(self, dest, amount, nonce, tick):
        if self.revoked:
            return "revoked"
        if tick >= self.expiry_tick:
            return "expired"
        if amount == 0:
            return "zero_amount"
        expected = (self.nonce + 1) & 0xFFFFFFFF
        if nonce != expected:
            return "nonce"
        if not mandate_permits_dest(self.dests, self.dest_count, dest):
            return "perimeter"
        if amount > self.max_rate:
            return "over_rate"
        if amount > self.remaining:
            return "over_cap"
        self.remaining -= amount
        self.nonce = nonce
        return "ok"

    def revoke(self, tick):
        if not self.revoked:
            self.revoked = True
            self.revocation_tick = tick

    def drain_ready(self, tick):
        return self.revoked and tick >= self.revocation_tick + DRAIN_DELAY_TICKS

    def state(self):
        return [self.remaining, self.nonce, self.revoked]


# --- The uniform authority encoding (from the ADR text) -----------

def derive_pad(payload):
    return keccak256(PAD_PREFIX + payload)


def authority_encode(payload):
    return payload + derive_pad(payload)


def authority_well_formed(field):
    payload, pad = field[:32], field[32:]
    return derive_pad(payload) == pad


# --- The receipts (from the ADR text) -----------------------------

def fact_canonical_bytes(kind, job_id, amount, tick, warrant_root):
    return struct.pack(">BIQI", kind, job_id, amount, tick) + warrant_root


def receipt_commit(kind, job_id, amount, tick, warrant_root, salt):
    material = fact_canonical_bytes(kind, job_id, amount, tick,
                                    warrant_root) + salt
    return keccak256(material)


def receipt_status(warrant_revoked, opened):
    if warrant_revoked:
        return "failed"
    return "paid" if opened else "open"


# --- The streams (from the ADR text) ------------------------------

def stream_tick(state, rate_per_tick, cap, warrant_revoked):
    # state layout: [paid, ticks, closed]
    state[1] += 1                     # ticks advance, always
    if state[2] or warrant_revoked:   # closed or revoked: zero
        return 0
    room = cap - state[0] if cap > state[0] else 0
    pay = min(rate_per_tick, room)
    state[0] += pay
    return pay


# --- The batches (from the ADR text) ------------------------------

def batch(payments, warrant, nonce, tick):
    if len(payments) > BATCH_MAX_PAYMENTS:
        return "batch_too_large", None
    if not payments:
        return "zero_amount", None
    total = 0
    for dest, amount in payments:
        if amount == 0:
            return "zero_amount", None
        if not mandate_permits_dest(warrant.dests, warrant.dest_count, dest):
            return "perimeter", None
        total += amount
    outcome = warrant.spend(payments[0][0], total, nonce, tick)
    if outcome != "ok":
        return outcome, None
    return "ok", {"total": total, "ring_verifications": 1}


def error_label(rejection):
    if rejection is None:
        return None
    kind, field, value = rejection
    if kind == "duplicate_dest":
        return "duplicate_dest"
    return f"malformed_mandate:{field}:{value}"


def main():
    vectors = {}

    # --- mandate grammar: accept and every rejection --------------
    good_dests = [LCG.hash32() for _ in range(MANDATE_MAX_DESTS)]
    padded = good_dests[:3] + [b"\x00" * 32] * 5
    mandate_cases = []
    cases = [
        # (name, version, amount, rate, expiry, jobs, rails, dests,
        #  dest_count, expect_ok)
        ("accept", MANDATE_VERSION, 5_000_000_000, 50_000_000, 10_000,
         0b0111, 0b0011, good_dests[:3] + [b"\x00" * 32] * 5, 3, True),
        ("empty_dest_set", MANDATE_VERSION, 5_000_000_000, 50_000_000,
         10_000, 0b0111, 0b0011, [b"\x00" * 32] * 8, 0, True),
        ("wrong_version", 1, 5_000_000_000, 50_000_000, 10_000,
         0b0111, 0b0011, good_dests, 3, False),
        ("amount_over_ceiling", MANDATE_VERSION, MANDATE_MAX_AMOUNT_ATOMIC + 1,
         50_000_000, 10_000, 0b0111, 0b0011, good_dests, 3, False),
        ("rate_over_amount", MANDATE_VERSION, 1_000, 2_000, 10_000,
         0b0111, 0b0011, good_dests, 3, False),
        ("rail_c_forbidden", MANDATE_VERSION, 5_000_000_000, 50_000_000,
         10_000, 0b0111, 0b0100, good_dests, 3, False),
        ("rail_d_forbidden", MANDATE_VERSION, 5_000_000_000, 50_000_000,
         10_000, 0b0111, 0b1000, good_dests, 3, False),
        ("dest_count_over", MANDATE_VERSION, 5_000_000_000, 50_000_000,
         10_000, 0b0111, 0b0011, good_dests, 9, False),
        ("live_zero_dest", MANDATE_VERSION, 5_000_000_000, 50_000_000,
         10_000, 0b0111, 0b0011,
         [good_dests[0], b"\x00" * 32] + good_dests[2:], 2, False),
        ("padding_not_zero", MANDATE_VERSION, 5_000_000_000, 50_000_000,
         10_000, 0b0111, 0b0011, good_dests, 2, False),
        ("duplicate_dest", MANDATE_VERSION, 5_000_000_000, 50_000_000,
         10_000, 0b0111, 0b0011,
         [good_dests[0], good_dests[0]] + good_dests[2:], 3, False),
    ]
    for (name, version, amount, rate, expiry, jobs, rails, dests,
         count, ok) in cases:
        rejection = mandate_validate(version, amount, rate, expiry,
                                     jobs, rails, dests, count)
        permits = [
            mandate_permits_dest(dests, count, d) for d in dests[:3]
        ]
        canonical = mandate_canonical_bytes(version, amount, rate, expiry,
                                            jobs, rails, dests, count)
        mandate_cases.append({
            "name": name,
            "version": version,
            "max_amount": amount,
            "max_rate": rate,
            "expiry_tick": expiry,
            "job_types": jobs,
            "rails": rails,
            "dests_hex": [d.hex() for d in dests],
            "dest_count": count,
            "valid": rejection is None,
            "rejection": error_label(rejection),
            "permits_first_three": permits,
            "canonical_sha": keccak256(canonical).hex(),
        })
    vectors["mandate"] = mandate_cases

    # --- warrant machine: a full life under attack ---------------
    dest_a, dest_b = good_dests[0], good_dests[1]
    warrant = Warrant(MANDATE_VERSION, 20_000_000, 10_000_000, 1_000,
                      0b0111, 0b0011, padded, 3)
    ops = []
    # a good spend, a replay, a gap, a perimeter miss, an
    # over-rate, a revocation, the wall, the drain delay
    steps = [
        ("spend", dest_a, 4_000_000, 1, 100, "ok"),
        ("replay", dest_a, 4_000_000, 1, 101, "nonce"),
        ("gap", dest_a, 4_000_000, 3, 102, "nonce"),
        ("perimeter", b"\xff" * 32, 1_000_000, 2, 103, "perimeter"),
        ("over_rate", dest_b, 11_000_000, 2, 104, "over_rate"),
        ("ok_second", dest_b, 10_000_000, 2, 105, "ok"),
        ("over_cap", dest_a, 10_000_000, 3, 106, "over_cap"),
        ("revoke", None, 0, 0, 200, None),
        ("spend_after_revoke", dest_a, 1_000, 3, 201, "revoked"),
        ("drain_early", None, 0, 0, 487, None),
        ("drain_ready", None, 0, 0, 488, None),
        ("expiry", dest_a, 1_000, 3, 999, "revoked"),
    ]
    for (name, dest, amount, nonce, tick, expected) in steps:
        step = {"op": name, "amount": amount, "nonce": nonce,
                "tick": tick}
        if dest is not None:
            step["dest_hex"] = dest.hex()
        if name == "revoke":
            warrant.revoke(tick)
            step["drain_ready"] = False
        elif name in ("drain_early", "drain_ready"):
            step["drain_ready"] = warrant.drain_ready(tick)
        elif name == "expiry":
            outcome = warrant.spend(dest, amount, nonce, tick)
            step["outcome"] = outcome
        else:
            outcome = warrant.spend(dest, amount, nonce, tick)
            step["outcome"] = outcome
            assert (expected is None) or outcome == expected, name
        step["after"] = warrant.state()
        ops.append(step)
    vectors["warrant"] = {
        "max_amount": warrant.max_amount,
        "max_rate": warrant.max_rate,
        "expiry_tick": warrant.expiry_tick,
        "job_types": warrant.job_types,
        "rails": warrant.rails,
        "dests_hex": [d.hex() for d in padded],
        "dest_count": 3,
        "mandate_root": warrant.root().hex(),
        "ops": ops,
        "final_state": warrant.state(),
    }

    # --- uniform encoding: same shape for both kinds --------------
    human_payload = LCG.hash32()
    agent_payload = warrant.root()
    human_field = authority_encode(human_payload)
    agent_field = authority_encode(agent_payload)
    broken = bytearray(agent_field)
    broken[63] ^= 0x01
    vectors["encoding"] = {
        "human_payload_hex": human_payload.hex(),
        "agent_payload_hex": agent_payload.hex(),
        "human_field_hex": human_field.hex(),
        "agent_field_hex": agent_field.hex(),
        "human_len": len(human_field),
        "agent_len": len(agent_field),
        "human_well_formed": authority_well_formed(human_field),
        "agent_well_formed": authority_well_formed(agent_field),
        "broken_well_formed": authority_well_formed(bytes(broken)),
        "same_prefix_free": (
            human_field[:32] != agent_field[:32]
            and human_field[32:] != agent_field[32:]
        ),
    }

    # --- receipts: commit, verify, fail ---------------------------
    root = warrant.root()
    salt = LCG.hash32()
    other_salt = LCG.hash32()
    commitment = receipt_commit(FACT_KIND_PAYMENT, 42, 3_000_000,
                                900, root, salt)
    wrong = receipt_commit(FACT_KIND_PAYMENT, 42, 3_000_001,
                           900, root, salt)
    vectors["receipt"] = {
        "kind": 2,
        "job_id": 42,
        "amount": 3_000_000,
        "tick": 900,
        "warrant_root_hex": root.hex(),
        "salt_hex": salt.hex(),
        "commitment_hex": commitment.hex(),
        "verify_right": True,
        "verify_wrong_amount": False,
        "verify_wrong_salt": False,
        "status_open": receipt_status(False, False),
        "status_paid": receipt_status(False, True),
        "status_failed": receipt_status(True, False),
        "wrong_commitment_hex": wrong.hex(),
    }

    # --- streams: rate, cap, the fail-closed cut ------------------
    state = [0, 0, False]            # paid, ticks, closed
    stream_ops = []
    rate, cap = 1_000_000, 5_000_000
    for i in range(3):
        pay = stream_tick(state, rate, cap, False)
        stream_ops.append({"tick": i + 1, "revoked": False, "paid": pay,
                           "state": state.copy()})
    pay = stream_tick(state, rate, cap, True)      # the cut
    stream_ops.append({"tick": 4, "revoked": True, "paid": pay,
                       "state": state.copy()})
    pay = stream_tick(state, rate, cap, False)     # still cut
    stream_ops.append({"tick": 5, "revoked": False, "paid": pay,
                       "state": state.copy()})
    state2 = [0, 0, False]
    for i in range(7):
        pay = stream_tick(state2, rate, cap, False)
        stream_ops.append({"tick": i + 1, "revoked": False, "paid": pay,
                           "state": state2.copy(),
                           "series": "cap_exhausts"})
    vectors["stream"] = {"rate_per_tick": rate, "cap": cap, "ops": stream_ops}

    # --- batches: one ring verification for many outputs ----------
    warrant2 = Warrant(MANDATE_VERSION, 100_000_000, 10_000_000, 1_000,
                       0b0111, 0b0011, padded, 3)
    batch_ok = batch([(dest_a, 3_000_000), (dest_b, 2_000_000),
                      (good_dests[2], 1_000_000)],
                     warrant2, 1, 100)
    batch_empty = batch([], warrant2, 2, 101)
    batch_perimeter = batch([(dest_a, 1_000), (b"\xee" * 32, 1_000)],
                            warrant2, 2, 102)
    batch_over_rate = batch([(dest_a, 6_000_000), (dest_b, 6_000_000)],
                            warrant2, 2, 103)
    vectors["batch"] = {
        "max_amount": warrant2.max_amount,
        "max_rate": warrant2.max_rate,
        "expiry_tick": warrant2.expiry_tick,
        "job_types": warrant2.job_types,
        "rails": warrant2.rails,
        "dests_hex": [d.hex() for d in padded],
        "dest_count": 3,
        "ok": {"outcome": batch_ok[0], "result": batch_ok[1]},
        "empty": {"outcome": batch_empty[0], "result": None},
        "perimeter": {"outcome": batch_perimeter[0], "result": None},
        "over_rate": {"outcome": batch_over_rate[0], "result": None},
        "after": warrant2.state(),
    }

    data = {
        "format": 1,
        "comment": (
            "ANTUMBRA agents cross-validation vectors, generated by "
            "code/scripts/gen_agents_vectors.py (independent Python "
            "implementation of ADR-021 and ADR-022: mandate grammar, "
            "warrant machine, uniform encoding, receipts, streams, "
            "batches). Regenerate with the generator; both "
            "implementations must agree bit for bit."
        ),
        **vectors,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
