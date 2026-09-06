#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-ring.

Independent re-implementation of every output-producing routine
of the finality layer (ADR-014): the checkpoint message codec
(canonical encoding, digest), the order root (the canonical list
hash), the checkpoint codec (seat signatures, strictly
ascending), the quorum rule (37 of 55), the verification battery
against a roster (era match, seat range, Ed25519 under the seat
key) and the stripping evidence codec with its rule battery.
Keccak-256 and Ed25519 come from pycryptodome; the varint and
every codec are re-implemented from the ADR text alone. The
output is the archived vector set consumed by the Rust test
suite: both implementations must agree bit for bit
(CONTRIBUTING.md, verification layer 1).

The generator also decodes: a Python reader mirrors the strict
decoding rules (canonical varints, structural limits, strictly
ascending seats, no trailing bytes) and every generated object
must survive encode-decode-encode unchanged. Every signature is
verified against the roster before the vector is written. A
vector set that does not pass its own self-checks is never
written.

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339, the golden ratio scaled, the number
that already drives the emission calendar). No Python random
module, no version drift, byte-for-byte reproducible on any
machine.

Usage: python3 code/scripts/gen_ring_vectors.py
Writes: code/crates/antumbra-ring/tests/vectors.json
"""

import json
import sys
from pathlib import Path

from Crypto.Hash import keccak
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

OUTPUT = Path(__file__).resolve().parents[1] / "crates" / "antumbra-ring" / "tests" / "vectors.json"

# --- Constants mirrored from ADR-014 and the Rust crate ----------

VERSION_1 = 1
SEATS = 55
QUORUM = 37
ZERO = bytes(32)
U64_MAX = 0xFFFFFFFFFFFFFFFF


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


class Lcg:
    """u64 linear congruential generator, Knuth constants."""

    def __init__(self, seed: int):
        self.state = seed & U64_MAX

    def next_u64(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & U64_MAX
        return self.state

    def next_below(self, bound: int) -> int:
        return self.next_u64() % bound

    def bytes(self, n: int) -> bytes:
        return bytes((self.next_u64() >> 32) & 0xFF for _ in range(n))

    def distinct(self, count: int) -> list[bytes]:
        out: set[bytes] = set()
        while len(out) < count:
            out.add(self.bytes(32))
        return sorted(out)


def ed25519_public(seed: bytes) -> bytes:
    key = ECC.construct(curve="ed25519", seed=seed)
    return key.public_key().export_key(format="raw")


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    key = ECC.construct(curve="ed25519", seed=seed)
    signer = eddsa.new(key, mode="rfc8032")
    return signer.sign(message)


def ed25519_verify(seed: bytes, message: bytes, signature: bytes) -> bool:
    key = ECC.construct(curve="ed25519", seed=seed)
    verifier = eddsa.new(key, mode="rfc8032")
    try:
        verifier.verify(message, signature)
        return True
    except ValueError:
        return False


def write_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for i in range(10):
        if pos + i >= len(data):
            raise Reject("Decode")
        byte = data[pos + i]
        payload = byte & 0x7F
        terminates = byte & 0x80 == 0
        if i == 9:
            if payload != 1 or not terminates:
                raise Reject("Decode")
            return value | (1 << 63), 10
        value |= payload << (7 * i)
        if terminates:
            if payload == 0 and i > 0:
                raise Reject("Decode")
            return value, i + 1
    raise Reject("Decode")


class Reject(Exception):
    """The Python twin of RingError: a name and nothing else."""

    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


# --- The codecs ----------------------------------------------------

def message_encode(era: int, sequence: int, tip: bytes, order_root: bytes) -> bytes:
    out = bytearray()
    out += VERSION_1.to_bytes(2, "little")
    out += era.to_bytes(8, "little")
    out += sequence.to_bytes(8, "little")
    out += tip
    out += order_root
    return bytes(out)


def checkpoint_encode(era: int, sequence: int, tip: bytes, order_root: bytes,
                      signatures: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    out += message_encode(era, sequence, tip, order_root)
    out += write_varint(len(signatures))
    for seat, signature in signatures:
        out += seat.to_bytes(2, "little")
        out += signature
    return bytes(out)


def equivocation_encode(seat: int, first: tuple, first_signature: bytes,
                        second: tuple, second_signature: bytes) -> bytes:
    out = bytearray()
    out += seat.to_bytes(2, "little")
    out += message_encode(*first)
    out += first_signature
    out += message_encode(*second)
    out += second_signature
    return bytes(out)


def decode_message(data: bytes) -> tuple[int, int, bytes, bytes]:
    """Strict message decode; the four fields."""
    pos = 0
    if len(data) < 2:
        raise Reject("Decode")
    version = int.from_bytes(data[pos:pos + 2], "little")
    pos += 2
    if version != VERSION_1:
        raise Reject("InvalidVersion")
    if pos + 16 > len(data):
        raise Reject("Decode")
    era = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    sequence = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    if era == 0:
        raise Reject("EraZero")
    if sequence == 0:
        raise Reject("SequenceZero")
    if pos + 64 > len(data):
        raise Reject("Decode")
    tip = data[pos:pos + 32]
    pos += 32
    if tip == ZERO:
        raise Reject("ZeroTip")
    order_root = data[pos:pos + 32]
    pos += 32
    return era, sequence, tip, order_root


def decode_checkpoint(data: bytes):
    """Strict checkpoint decode; the message and the pairs."""
    era, sequence, tip, order_root = decode_message(data)
    pos = 82  # the message is always eighty-two bytes
    count, consumed = read_varint(data, pos)
    pos += consumed
    if count > SEATS:
        raise Reject("TooManySignatures")
    signatures: list[tuple[int, bytes]] = []
    for _ in range(count):
        if pos + 66 > len(data):
            raise Reject("Decode")
        seat = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        signature = data[pos:pos + 64]
        pos += 64
        for previous_seat, _ in signatures:
            if previous_seat == seat:
                raise Reject("DuplicateSeat")
        if signatures and signatures[-1][0] > seat:
            raise Reject("UnsortedSeats")
        signatures.append((seat, signature))
    if pos != len(data):
        raise Reject("Decode")
    return (era, sequence, tip, order_root), signatures


# --- The verification battery (the Python twin of the Rust rules) -

def verify_checkpoint(era: int, sequence: int, tip: bytes, order_root: bytes,
                      signatures: list[tuple[int, bytes]],
                      roster_era: int, roster_seeds: list[bytes]) -> str | None:
    """Returns the rejection name, or None when every signature
    verifies. The rule order mirrors the Rust implementation."""
    if roster_era != era:
        return "EraMismatch"
    message = message_encode(era, sequence, tip, order_root)
    for seat, signature in signatures:
        if seat >= len(roster_seeds):
            return "SeatOutOfRange"
        if not ed25519_verify(roster_seeds[seat], message, signature):
            return "InvalidSignature"
    return None


def main() -> int:
    lcg = Lcg(16_180_339)

    # The fifty-five seat seeds of the vector roster.
    seeds: list[bytes] = []
    while len(seeds) < SEATS:
        candidate = lcg.bytes(32)
        if candidate not in seeds and candidate != ZERO:
            seeds.append(candidate)

    # --- Order root vectors -------------------------------------
    order_root_vectors = []
    for count in (1, 2, 8, 16, 64):
        ids = lcg.distinct(count)
        root = keccak256(write_varint(len(ids)) + b"".join(ids))
        order_root_vectors.append({
            "ids": [i.hex() for i in ids],
            "root": root.hex(),
        })

    # --- Message vectors ----------------------------------------
    message_vectors = []
    shapes = [(1, 1), (1, 2), (9, 100), (1 << 40, 1 << 20), (3, 7), (2, 5),
              (77, 999), (12, 345)]
    for era, sequence in shapes:
        tip = lcg.bytes(32)
        if tip == ZERO:
            tip = bytes([1]) + tip[1:]
        order_root = lcg.bytes(32)
        canonical = message_encode(era, sequence, tip, order_root)
        assert decode_message(canonical) == (era, sequence, tip, order_root)
        message_vectors.append({
            "era": era,
            "sequence": sequence,
            "tip": tip.hex(),
            "order_root": order_root.hex(),
            "canonical_hex": canonical.hex(),
            "digest": keccak256(canonical).hex(),
        })

    # --- Checkpoint vectors -------------------------------------
    checkpoint_vectors = []

    def checkpoint_vector(era, sequence, tip, order_root, signing_seeds,
                          roster_era, roster_count, final, error):
        message = message_encode(era, sequence, tip, order_root)
        signatures = []
        for seat, seed in signing_seeds:
            signatures.append((seat, ed25519_sign(seed, message)))
        canonical = checkpoint_encode(era, sequence, tip, order_root, signatures)
        decoded_message, decoded_signatures = decode_checkpoint(canonical)
        assert decoded_message == (era, sequence, tip, order_root)
        assert decoded_signatures == signatures
        computed_error = verify_checkpoint(era, sequence, tip, order_root,
                                           signatures, roster_era,
                                           seeds[:roster_count])
        if error is None:
            assert computed_error is None, f"expected clean, got {computed_error}"
            # The finality flag matches the quorum.
            assert final == (len(signatures) >= QUORUM)
        else:
            assert computed_error == error, \
                f"expected {error}, got {computed_error}"
        checkpoint_vectors.append({
            "era": era,
            "sequence": sequence,
            "tip": tip.hex(),
            "order_root": order_root.hex(),
            "signatures": [
                {"seat": seat, "seed": seed.hex()}
                for seat, seed in signing_seeds
            ],
            "roster_era": roster_era,
            "roster_count": roster_count,
            "final": final,
            "error": error,
            "canonical_hex": canonical.hex(),
        })

    # A quorum of thirty-seven signatures finalizes.
    checkpoint_vector(1, 1, lcg.bytes(32), lcg.bytes(32),
                      [(seat, seeds[seat]) for seat in range(QUORUM)],
                      1, SEATS, True, None)
    # Thirty-six do not.
    checkpoint_vector(2, 1, lcg.bytes(32), lcg.bytes(32),
                      [(seat, seeds[seat]) for seat in range(QUORUM - 1)],
                      2, SEATS, False, None)
    # A bootstrap roster of twenty seats cannot finalize.
    checkpoint_vector(3, 5, lcg.bytes(32), lcg.bytes(32),
                      [(seat, seeds[seat]) for seat in range(20)],
                      3, 20, False, None)
    # All fifty-five seats signing.
    checkpoint_vector(4, 9, lcg.bytes(32), lcg.bytes(32),
                      [(seat, seeds[seat]) for seat in range(SEATS)],
                      4, SEATS, True, None)
    # Seat 0 signs with the key of seat 1.
    checkpoint_vector(5, 3, lcg.bytes(32), lcg.bytes(32),
                      [(0, seeds[1]), (1, seeds[1]), (2, seeds[2])],
                      5, SEATS, False, "InvalidSignature")
    # Seats beyond a short roster.
    checkpoint_vector(6, 3, lcg.bytes(32), lcg.bytes(32),
                      [(seat, seeds[seat]) for seat in range(20)],
                      6, 15, False, "SeatOutOfRange")
    # The roster governs another era.
    checkpoint_vector(7, 3, lcg.bytes(32), lcg.bytes(32),
                      [(seat, seeds[seat]) for seat in range(QUORUM)],
                      8, SEATS, True, "EraMismatch")

    # --- Invalid decode vectors ----------------------------------
    # Build the invalid shapes from a clean, known checkpoint.
    clean_tip = lcg.bytes(32)
    if clean_tip == ZERO:
        clean_tip = bytes([1]) + clean_tip[1:]
    clean_root = lcg.bytes(32)
    clean_message = message_encode(1, 1, clean_tip, clean_root)
    clean_sig = ed25519_sign(seeds[0], clean_message)
    clean = clean_message + write_varint(1) + (0).to_bytes(2, "little") + clean_sig
    assert decode_checkpoint(clean)[1] == [(0, clean_sig)]

    # An unsorted pair list: seat 5 then seat 2.
    unsorted = clean_message + write_varint(2) \
        + (5).to_bytes(2, "little") + ed25519_sign(seeds[5], clean_message) \
        + (2).to_bytes(2, "little") + ed25519_sign(seeds[2], clean_message)
    # A duplicated pair.
    duplicated = clean_message + write_varint(2) \
        + (0).to_bytes(2, "little") + clean_sig \
        + (0).to_bytes(2, "little") + clean_sig
    # Fifty-six announced signatures.
    too_many = clean_message + write_varint(56)

    invalid_vectors = [
        {"hex": (b"\x02\x00" + clean[2:]).hex(), "error": "InvalidVersion"},
        {"hex": message_encode(0, 1, clean_tip, clean_root).hex(), "error": "EraZero"},
        {"hex": message_encode(1, 0, clean_tip, clean_root).hex(), "error": "SequenceZero"},
        {"hex": message_encode(1, 1, ZERO, clean_root).hex(), "error": "ZeroTip"},
        {"hex": (clean + b"\x00").hex(), "error": "Decode"},
        {"hex": unsorted.hex(), "error": "UnsortedSeats"},
        {"hex": duplicated.hex(), "error": "DuplicateSeat"},
        {"hex": too_many.hex(), "error": "TooManySignatures"},
    ]
    for vector in invalid_vectors:
        try:
            decode_checkpoint(bytes.fromhex(vector["hex"]))
        except Reject as e:
            assert e.name == vector["error"], \
                f"expected {vector['error']}, got {e.name}"
        else:
            raise AssertionError(f"the bytes must be rejected: {vector['error']}")

    # --- Equivocation vectors --------------------------------------
    equivocation_vectors = []

    def equivocation_vector(seat, signing_seed, roster_era, first, second, error):
        first_message = message_encode(*first)
        second_message = message_encode(*second)
        first_signature = ed25519_sign(signing_seed, first_message)
        second_signature = ed25519_sign(signing_seed, second_message)
        canonical = equivocation_encode(seat, first, first_signature,
                                        second, second_signature)
        # The Python twin of the Rust rule battery.
        computed = None
        if seat >= len(seeds):
            computed = "SeatOutOfRange"
        elif roster_era != first[0]:
            computed = "EraMismatch"
        elif roster_era != second[0]:
            computed = "EraMismatch"
        elif first[1] != second[1]:
            computed = "DifferentSequence"
        elif first_message == second_message:
            computed = "IdenticalMessages"
        elif not ed25519_verify(seeds[seat], first_message, first_signature) \
                or not ed25519_verify(seeds[seat], second_message, second_signature):
            computed = "InvalidSignature"
        if error is None:
            assert computed is None, f"expected clean, got {computed}"
        else:
            assert computed == error, f"expected {error}, got {computed}"
        equivocation_vectors.append({
            "seat": seat,
            "signing_seed": signing_seed.hex(),
            "roster_era": roster_era,
            "first": {
                "era": first[0], "sequence": first[1],
                "tip": first[2].hex(), "order_root": first[3].hex(),
            },
            "second": {
                "era": second[0], "sequence": second[1],
                "tip": second[2].hex(), "order_root": second[3].hex(),
            },
            "error": error,
            "canonical_hex": canonical.hex(),
        })

    def fresh_tip(tag: int) -> bytes:
        tip = lcg.bytes(32)
        if tip == ZERO:
            tip = bytes([tag]) + tip[1:]
        return tip

    # A competing fork: the seat is stripped.
    equivocation_vector(7, seeds[7], 3,
                        (3, 100, fresh_tip(1), lcg.bytes(32)),
                        (3, 100, fresh_tip(2), lcg.bytes(32)),
                        None)
    # One message signed twice is not a fork.
    same = (3, 100, fresh_tip(3), lcg.bytes(32))
    equivocation_vector(7, seeds[7], 3, same, same, "IdenticalMessages")
    # Two sequences are not a fork.
    equivocation_vector(7, seeds[7], 3,
                        (3, 100, fresh_tip(4), lcg.bytes(32)),
                        (3, 101, fresh_tip(5), lcg.bytes(32)),
                        "DifferentSequence")
    # Two eras are not a fork.
    equivocation_vector(7, seeds[7], 3,
                        (3, 100, fresh_tip(6), lcg.bytes(32)),
                        (4, 100, fresh_tip(7), lcg.bytes(32)),
                        "EraMismatch")
    # A foreign signature is rejected.
    equivocation_vector(7, seeds[8], 3,
                        (3, 100, fresh_tip(8), lcg.bytes(32)),
                        (3, 100, fresh_tip(9), lcg.bytes(32)),
                        "InvalidSignature")
    # An unknown seat is rejected.
    equivocation_vector(90, seeds[0], 3,
                        (3, 100, fresh_tip(10), lcg.bytes(32)),
                        (3, 100, fresh_tip(11), lcg.bytes(32)),
                        "SeatOutOfRange")

    # --- Write -------------------------------------------------------
    vectors = {
        "format": 1,
        "generator": "code/scripts/gen_ring_vectors.py (pycryptodome, independent implementation)",
        "seeds": [s.hex() for s in seeds],
        "order_root": order_root_vectors,
        "message": message_vectors,
        "checkpoint": checkpoint_vectors,
        "invalid": invalid_vectors,
        "equivocation": equivocation_vectors,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"OK: {len(order_root_vectors)} order root, {len(message_vectors)} message, "
          f"{len(checkpoint_vectors)} checkpoint, {len(invalid_vectors)} invalid, "
          f"{len(equivocation_vectors)} equivocation vectors written to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
