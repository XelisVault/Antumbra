#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-tx.

Independent re-implementation of every output-producing routine of
the transaction crate: the amount display format (ADR-008), the fee
schedule and the minimum-fee formula (ADR-009), and the version 1
transaction layer (ADR-010): canonical encoding, signing message,
per-input Ed25519 signatures, transaction id. Keccak-256 and
Ed25519 come from pycryptodome; the varint, the block base58, the
address format and the whole transaction codec are re-implemented
from the specification. The output is the archived vector set
consumed by the Rust test suite: both implementations must agree
bit for bit (CONTRIBUTING.md, verification layer 1).

The generator also decodes: a Python reader mirrors the strict
decoding rules (canonical varints, structural limits, strictly
ascending inputs, address checksum, no trailing bytes) and every
generated transaction must survive encode-decode-encode unchanged,
and every signature must verify. A vector set that does not pass
its own self-checks is never written.

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339, the golden ratio scaled, the number that
already drives the emission calendar). No Python random module, no
version drift, byte-for-byte reproducible on any machine.

Usage: python3 code/scripts/gen_tx_vectors.py
Writes: code/crates/antumbra-tx/tests/vectors.json
"""

import json
import sys
from pathlib import Path

from Crypto.Hash import keccak
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

OUTPUT = Path(__file__).resolve().parents[1] / "crates" / "antumbra-tx" / "tests" / "vectors.json"

# --- Constants mirrored from the ADRs and the Rust crate ----------

ATOMIC_PER_ATU = 100_000_000          # ADR-008
MAX_SUPPLY = 16_180_339 * ATOMIC_PER_ATU
FEE_BASE = 100_000                    # ADR-009
FEE_PER_KIB = 100_000
FEE_PER_RINGED_OUTPUT = 500_000
VERSION_1 = 1
TX_TAG_TRANSFER = 0
MAX_INPUTS = 64                       # ADR-010
MAX_OUTPUTS = 32
MAX_EXTRA_LEN = 512
U64_MAX = 0xFFFFFFFFFFFFFFFF

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]
FULL_BLOCK_BYTES = 8

NETWORKS = {"mainnet": ord("A"), "testnet": ord("T"), "devnet": ord("D")}


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


# --- Keccak-256 and Ed25519 (pycryptodome) ------------------------

def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256).update(data).digest()


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


# --- Canonical varints ---------------------------------------------

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
    """Strict reader: mirrors the Rust rules exactly."""
    value = 0
    for i in range(10):
        if pos + i >= len(data):
            raise ValueError("varint truncated")
        byte = data[pos + i]
        payload = byte & 0x7F
        terminates = byte & 0x80 == 0
        if i == 9:
            # The tenth byte exists only to carry the final bit.
            if payload != 1 or not terminates:
                raise ValueError("varint too wide")
            return value | (1 << 63), 10
        value |= payload << (7 * i)
        if terminates:
            if payload == 0 and i > 0:
                raise ValueError("non canonical varint")
            return value, i + 1
    raise ValueError("unreachable")


# --- Block base58 --------------------------------------------------

def encode_block(data: bytes) -> str:
    size = ENCODED_BLOCK_SIZES[len(data)]
    value = int.from_bytes(data, "big")
    out = ["1"] * size
    i = size
    while i > 0 and value > 0:
        i -= 1
        out[i] = ALPHABET[value % 58]
        value //= 58
    return "".join(out)


def base58_encode(data: bytes) -> str:
    out = []
    full = len(data) // FULL_BLOCK_BYTES
    for i in range(full):
        out.append(encode_block(data[i * 8:(i + 1) * 8]))
    remainder = data[full * 8:]
    if remainder:
        out.append(encode_block(remainder))
    return "".join(out)


# --- Amounts (ADR-008) ---------------------------------------------

def amount_text(atomic: int) -> str:
    whole = atomic // ATOMIC_PER_ATU
    frac = atomic % ATOMIC_PER_ATU
    return f"{whole}.{frac:08d} ATU"


# --- Fee schedule (ADR-009) ----------------------------------------

def kibibytes(size_bytes: int) -> int:
    chunks = -(-size_bytes // 1024)
    return max(1, chunks)


def minimum_fee(size_bytes: int, ringed_outputs: int) -> int | None:
    total = FEE_BASE + FEE_PER_KIB * kibibytes(size_bytes)
    total += FEE_PER_RINGED_OUTPUT * ringed_outputs
    if total > U64_MAX:
        return None
    return total


# --- Addresses -----------------------------------------------------

def address_raw(network_byte: int, spend: bytes, view: bytes) -> bytes:
    checksummed = bytes([network_byte]) + spend + view
    checksum = keccak256(checksummed)[:4]
    return checksummed + checksum


def view_seed_of(spend_seed: bytes) -> bytes:
    return keccak256(spend_seed)


# --- Transaction codec (ADR-010) -----------------------------------

def encode_transaction(inputs: list[dict], outputs: list[dict],
                       fee: int, extra: bytes) -> bytes:
    """The canonical encoding, mirroring the Rust layout byte for byte.

    input  := tx hash:32B | index:u32 LE | key:32B | signature:64B
    output := address:69B raw | amount:u64 LE
    """
    out = bytearray()
    out += VERSION_1.to_bytes(2, "little")
    out.append(TX_TAG_TRANSFER)
    out += fee.to_bytes(8, "little")
    out += write_varint(len(inputs))
    for i in inputs:
        out += i["tx"] + i["index"].to_bytes(4, "little")
        out += i["key"] + i["signature"]
    out += write_varint(len(outputs))
    for o in outputs:
        out += o["raw"] + o["amount"].to_bytes(8, "little")
    out += write_varint(len(extra)) + extra
    return bytes(out)


def encode_signing_message(inputs: list[dict], outputs: list[dict],
                           fee: int, extra: bytes) -> bytes:
    zeroed = [dict(i, signature=bytes(64)) for i in inputs]
    return encode_transaction(zeroed, outputs, fee, extra)


def transaction_id(canonical: bytes) -> bytes:
    return keccak256(canonical)


def decode_transaction(data: bytes) -> dict:
    """Strict decoder: mirrors every rule of the Rust decoder.

    Returns the decoded fields; raises ValueError on the first
    violation. Curve-point validity of keys is not checked here:
    pycryptodome cannot validate arbitrary compressed points, the
    vectors only contain valid keys, and that check lives in the
    Rust decoder.
    """
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise ValueError("eof")
        chunk = data[pos:pos + n]
        pos += n
        return chunk

    version = int.from_bytes(take(2), "little")
    if version != VERSION_1:
        raise ValueError(f"version {version}")
    tag = take(1)[0]
    if tag != TX_TAG_TRANSFER:
        raise ValueError(f"tag {tag}")
    fee = int.from_bytes(take(8), "little")

    count, used = read_varint(data, pos)
    pos += used
    if count > MAX_INPUTS:
        raise ValueError(f"{count} inputs")
    inputs = []
    for _ in range(count):
        tx_hash = take(32)
        index = int.from_bytes(take(4), "little")
        key = take(32)
        signature = take(64)
        inputs.append({"tx": tx_hash, "index": index, "key": key, "signature": signature})
    for a, b in zip(inputs, inputs[1:]):
        if (a["tx"], a["index"]) >= (b["tx"], b["index"]):
            raise ValueError("inputs not strictly ascending")

    count, used = read_varint(data, pos)
    pos += used
    if count > MAX_OUTPUTS:
        raise ValueError(f"{count} outputs")
    outputs = []
    for _ in range(count):
        raw = take(69)
        network_byte = raw[0]
        if network_byte not in NETWORKS.values():
            raise ValueError("unknown network byte")
        spend, view = raw[1:33], raw[33:65]
        if keccak256(raw[:65])[:4] != raw[65:69]:
            raise ValueError("address checksum")
        amount = int.from_bytes(take(8), "little")
        outputs.append({"raw": raw, "amount": amount,
                        "spend": spend, "view": view,
                        "network_byte": network_byte})
    extra_len, used = read_varint(data, pos)
    pos += used
    if extra_len > MAX_EXTRA_LEN:
        raise ValueError(f"extra {extra_len}")
    if extra_len > len(data) - pos:
        raise ValueError("extra over announced")
    extra = take(extra_len)
    if pos != len(data):
        raise ValueError("trailing bytes")

    return {"fee": fee, "inputs": inputs, "outputs": outputs, "extra": extra}


# --- Self-checks: the reference must agree with itself ------------

def self_check() -> None:
    # Keccak-256 official vector for the empty string.
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    # RFC 8032 section 7.1 test 1.
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    assert ed25519_public(seed).hex() == (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    assert ed25519_sign(seed, b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    # Amount display: eight decimals, no float.
    assert amount_text(0) == "0.00000000 ATU"
    assert amount_text(ATOMIC_PER_ATU) == "1.00000000 ATU"
    assert amount_text(12_345_678) == "0.12345678 ATU"
    assert amount_text(MAX_SUPPLY) == "16180339.00000000 ATU"
    # Fee boundaries: per started kibibyte, minimum one.
    assert minimum_fee(0, 0) == 200_000
    assert minimum_fee(1024, 0) == minimum_fee(1, 0) == 200_000
    assert minimum_fee(1025, 0) == 300_000
    assert minimum_fee(2048, 3) == 300_000 + 1_500_000
    assert minimum_fee(2 ** 63, 0) is None
    # Varint strict reader on the classic forms.
    assert read_varint(b"\x00", 0) == (0, 1)
    assert read_varint(b"\xac\x02", 0) == (300, 2)
    for bad in (b"\x80\x00", b"\xff\x00", b"\x80", b"\xff" * 10):
        try:
            read_varint(bad, 0)
            raise AssertionError(f"{bad.hex()} should be rejected")
        except ValueError:
            pass


# --- Vector generation ---------------------------------------------

def build_transaction(rng: Lcg, network: str, n_inputs: int,
                      n_outputs: int, extra_len: int) -> dict:
    """Builds one deterministic signed transaction vector."""

    # Inputs: distinct seeds, random references, sorted ascending.
    inputs = []
    for _ in range(n_inputs):
        seed = rng.bytes(32)
        ref = (rng.bytes(32), rng.next_below(8))
        inputs.append({"seed": seed, "tx": ref[0], "index": ref[1]})
    inputs.sort(key=lambda i: (i["tx"], i["index"]))
    for i in inputs:
        i["key"] = ed25519_public(i["seed"])
        i["signature"] = bytes(64)  # zeroed until signing

    # Outputs: distinct seeds, random nonzero amounts.
    outputs = []
    for _ in range(n_outputs):
        seed = rng.bytes(32)
        spend = ed25519_public(seed)
        view = ed25519_public(view_seed_of(seed))
        network_byte = NETWORKS[network]
        raw = address_raw(network_byte, spend, view)
        amount = rng.next_below(10 ** 12) + 1
        outputs.append({"seed": seed, "raw": raw, "amount": amount,
                        "address": base58_encode(raw)})

    extra = rng.bytes(extra_len)

    # Fee: the field occupies eight bytes whatever its value, so
    # the size is stable; one pass computes the minimum, a
    # deterministic multiplier above it sets the fee.
    probe = encode_transaction(inputs, outputs, 0, extra)
    minimum = minimum_fee(len(probe), 0)
    assert minimum is not None
    fee = minimum * (1 + rng.next_below(4))

    # Sign every input over the signing message.
    message = encode_signing_message(inputs, outputs, fee, extra)
    for i in inputs:
        i["signature"] = ed25519_sign(i["seed"], message)

    canonical = encode_transaction(inputs, outputs, fee, extra)

    # --- Self-checks on this very vector ---
    decoded = decode_transaction(canonical)
    assert decoded["fee"] == fee
    assert decoded["extra"] == extra
    assert len(decoded["inputs"]) == n_inputs
    assert len(decoded["outputs"]) == n_outputs
    for a, b in zip(decoded["inputs"], inputs):
        assert a["tx"] == b["tx"] and a["index"] == b["index"]
        assert a["key"] == b["key"] and a["signature"] == b["signature"]
    for a, b in zip(decoded["outputs"], outputs):
        assert a["raw"] == b["raw"] and a["amount"] == b["amount"]
    assert encode_transaction(decoded["inputs"], decoded["outputs"],
                              decoded["fee"], decoded["extra"]) == canonical
    assert fee >= minimum_fee(len(canonical), 0)
    for i in inputs:
        assert ed25519_verify(i["seed"], message, i["signature"])
    assert transaction_id(canonical) == keccak256(canonical)
    assert message == encode_signing_message(
        decoded["inputs"], decoded["outputs"], fee, extra)

    return {
        "network": network,
        "inputs": [
            {
                "seed": i["seed"].hex(),
                "tx": i["tx"].hex(),
                "index": i["index"],
                "key": i["key"].hex(),
                "signature": i["signature"].hex(),
            }
            for i in inputs
        ],
        "outputs": [
            {
                "seed": o["seed"].hex(),
                "address": o["address"],
                "amount": o["amount"],
            }
            for o in outputs
        ],
        "fee": fee,
        "extra_hex": extra.hex(),
        "canonical_hex": canonical.hex(),
        "signing_message_hex": message.hex(),
        "tx_id": transaction_id(canonical).hex(),
    }


def main() -> int:
    self_check()
    rng = Lcg(16180339)

    # Eight transactions: ordinary shapes, the extra-data boundary,
    # the input limit, a wide output fan, and all three networks.
    shapes = [
        ("mainnet", 1, 1, 0),
        ("mainnet", 1, 2, 16),
        ("testnet", 2, 1, 8),
        ("mainnet", 3, 3, 32),
        ("devnet", 5, 4, 0),
        ("testnet", 2, 2, 512),
        ("mainnet", 64, 2, 0),
        ("devnet", 8, 16, 7),
    ]
    transaction_vectors = [
        build_transaction(rng, network, n_in, n_out, extra_len)
        for network, n_in, n_out, extra_len in shapes
    ]

    # Amount display vectors: fixed edges then pseudorandom values.
    amount_vectors = [
        {"atomic": 0, "text": amount_text(0)},
        {"atomic": 1, "text": amount_text(1)},
        {"atomic": ATOMIC_PER_ATU, "text": amount_text(ATOMIC_PER_ATU)},
        {"atomic": 12_345_678, "text": amount_text(12_345_678)},
        {"atomic": MAX_SUPPLY, "text": amount_text(MAX_SUPPLY)},
        {"atomic": MAX_SUPPLY + 1, "text": amount_text(MAX_SUPPLY + 1)},
    ]
    for _ in range(12):
        atomic = rng.next_below(U64_MAX)
        amount_vectors.append({"atomic": atomic, "text": amount_text(atomic)})

    # Fee vectors: kibibyte boundaries, ring counts, the overflow.
    fee_vectors = []
    for size in (0, 1, 1023, 1024, 1025, 2047, 2048, 2049, 4096, 11_542):
        for ringed in (0, 1, 3):
            fee_vectors.append({
                "size": size,
                "ringed": ringed,
                "minimum": minimum_fee(size, ringed),
            })
    fee_vectors.append({"size": 2 ** 63, "ringed": 0, "minimum": None})

    vectors = {
        "format": 1,
        "generator": "code/scripts/gen_tx_vectors.py (pycryptodome, independent implementation)",
        "amount": amount_vectors,
        "fee": fee_vectors,
        "transaction": transaction_vectors,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"OK: {len(amount_vectors)} amount, {len(fee_vectors)} fee, "
          f"{len(transaction_vectors)} transaction vectors written to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
