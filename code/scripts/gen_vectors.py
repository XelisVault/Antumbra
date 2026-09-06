#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-primitives.

Independent re-implementation of every output-producing routine of
the primitives crate: Keccak-256 (pycryptodome), canonical LEB128
varints, block base58, the address format, and Ed25519 signatures
(RFC 8032, pycryptodome). The output is the archived vector set
consumed by the Rust test suite: both implementations must agree
bit for bit (CONTRIBUTING.md, verification layer 1).

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339, the golden ratio scaled, the number that
already drives the emission calendar). No Python random module, no
version drift, byte-for-byte reproducible on any machine.

Usage: python3 code/scripts/gen_vectors.py
Writes: code/crates/antumbra-primitives/tests/vectors.json
"""

import json
import sys
from pathlib import Path

from Crypto.Hash import keccak
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

OUTPUT = Path(__file__).resolve().parents[1] / "crates" / "antumbra-primitives" / "tests" / "vectors.json"

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Encoded sizes indexed by block byte count (0..=8); a full 8-byte
# block encodes to 11 characters.
ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]
FULL_BLOCK_BYTES = 8
FULL_BLOCK_CHARS = 11

MAINNET = ord("A")
TESTNET = ord("T")
DEVNET = ord("D")


class Lcg:
    """u64 linear congruential generator, Knuth constants."""

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next_u64(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.state

    def next_byte(self) -> int:
        return (self.next_u64() >> 32) & 0xFF

    def bytes(self, n: int) -> bytes:
        return bytes(self.next_byte() for _ in range(n))


# --- Keccak-256 -----------------------------------------------------------

def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256).update(data).digest()


# --- Canonical varints ----------------------------------------------------

def write_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


# --- Block base58 ---------------------------------------------------------

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


# --- Ed25519 keys ---------------------------------------------------------

def ed25519_public(seed: bytes) -> bytes:
    key = ECC.construct(curve="ed25519", seed=seed)
    return key.public_key().export_key(format="raw")


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    key = ECC.construct(curve="ed25519", seed=seed)
    signer = eddsa.new(key, mode="rfc8032")
    return signer.sign(message)


# --- Address format -------------------------------------------------------

def address_bytes(network_byte: int, spend: bytes, view: bytes) -> bytes:
    checksummed = bytes([network_byte]) + spend + view
    checksum = keccak256(checksummed)[:4]
    return checksummed + checksum


# --- Self-checks: the reference must agree with the published standards --

def self_check() -> None:
    # Keccak-256 official vector for the empty string.
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    # Varint canonical forms.
    assert write_varint(0) == b"\x00"
    assert write_varint(300) == b"\xac\x02"
    # Block base58 structural facts.
    assert base58_encode(bytes(8)) == "1" * 11
    assert base58_encode(b"\x01") == "12"
    # RFC 8032 section 7.1 test 1: seed, public key, signature.
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    public = ed25519_public(seed)
    assert public.hex() == (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ), f"ed25519 public mismatch: {public.hex()}"
    signature = ed25519_sign(seed, b"")
    assert signature.hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ), f"ed25519 signature mismatch: {signature.hex()}"
    # RFC 8032 section 7.1 test 2.
    seed2 = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    assert ed25519_public(seed2).hex() == (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    assert ed25519_sign(seed2, b"\x72").hex() == (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )


# --- Vector generation ----------------------------------------------------

def main() -> int:
    self_check()
    rng = Lcg(16180339)

    # Keccak-256: fixed strings then pseudorandom inputs of every
    # interesting length, including the full-block boundary 64.
    keccak_vectors = []
    fixed_inputs = [b"", b"abc", b"ANTUMBRA", b"The quick brown fox jumps over the lazy dog", bytes(64), bytes(65)]
    for data in fixed_inputs:
        keccak_vectors.append({"hex": data.hex(), "digest": keccak256(data).hex()})
    for length in range(0, 81):
        data = rng.bytes(length)
        keccak_vectors.append({"hex": data.hex(), "digest": keccak256(data).hex()})

    # Varints: boundaries then pseudorandom values.
    varint_vectors = [
        {"value": 0, "hex": write_varint(0).hex()},
        {"value": 127, "hex": write_varint(127).hex()},
        {"value": 128, "hex": write_varint(128).hex()},
        {"value": 16383, "hex": write_varint(16383).hex()},
        {"value": 16384, "hex": write_varint(16384).hex()},
        {"value": 2**32 - 1, "hex": write_varint(2**32 - 1).hex()},
        {"value": 2**63, "hex": write_varint(2**63).hex()},
        {"value": 2**64 - 1, "hex": write_varint(2**64 - 1).hex()},
    ]
    for _ in range(64):
        value = rng.next_u64()
        varint_vectors.append({"value": value, "hex": write_varint(value).hex()})

    # Block base58: fixed edge cases then pseudorandom lengths.
    base58_vectors = [
        {"hex": "", "text": base58_encode(b"")},
        {"hex": "01", "text": base58_encode(b"\x01")},
        {"hex": "00", "text": base58_encode(b"\x00")},
        {"hex": "00" * 8, "text": base58_encode(bytes(8))},
        {"hex": "00" * 9, "text": base58_encode(bytes(9))},
        {"hex": "ff" * 8, "text": base58_encode(b"\xff" * 8)},
        {"hex": "ff" * 7, "text": base58_encode(b"\xff" * 7)},
    ]
    for length in range(1, 81):
        data = rng.bytes(length)
        base58_vectors.append({"hex": data.hex(), "text": base58_encode(data)})

    # Addresses: a grid of seeds and networks.
    networks = [
        ("mainnet", MAINNET),
        ("testnet", TESTNET),
        ("devnet", DEVNET),
    ]
    address_vectors = []
    for i in range(8):
        seed = rng.bytes(32)
        spend_seed = seed
        view_seed = keccak256(spend_seed)
        spend = ed25519_public(spend_seed)
        view = ed25519_public(view_seed)
        for name, byte in networks:
            address_vectors.append({
                "seed": seed.hex(),
                "network": name,
                "address": base58_encode(address_bytes(byte, spend, view)),
            })

    # Signatures: deterministic seeds, pseudorandom messages.
    signature_vectors = []
    for i in range(24):
        seed = rng.bytes(32)
        message = rng.bytes(rng.next_u64() % 128)
        signature_vectors.append({
            "seed": seed.hex(),
            "message_hex": message.hex(),
            "signature_hex": ed25519_sign(seed, message).hex(),
        })

    vectors = {
        "format": 1,
        "generator": "code/scripts/gen_vectors.py (pycryptodome, independent implementation)",
        "keccak256": keccak_vectors,
        "varint": varint_vectors,
        "base58": base58_vectors,
        "address": address_vectors,
        "signature": signature_vectors,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"OK: {len(keccak_vectors)} keccak, {len(varint_vectors)} varint, "
          f"{len(base58_vectors)} base58, {len(address_vectors)} address, "
          f"{len(signature_vectors)} signature vectors written to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
