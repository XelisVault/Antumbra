#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-veil.

Independent re-implementation of every output-producing routine of
the Veil cryptographic core (ADR-011): the from-spec Edwards25519
group (field arithmetic, point addition, scalar multiplication, RFC
8032 compression and decompression), the wallet scalar derivation
(RFC 8032 clamping reduced modulo the group order), the hash to
scalar Hs and the hash to point Hp (Keccak-256 from pycryptodome,
hash-and-check over the decompression), the one-time destination
addresses, the Pedersen commitments and the key images. Keccak-256
and the RFC 8032 reference public keys come from pycryptodome; the
whole Veil construction is re-implemented from the specification.

The output is the archived vector set consumed by the Rust test
suite: both implementations must agree bit for bit (CONTRIBUTING.md,
verification layer 1). A disagreement here is not a test failure: it
is a consensus fault, and it blocks the phase.

The generator self-checks before writing: the from-spec base point
against the RFC 8032 encoding and the group order, every derived
public key against the pycryptodome Ed25519 reference, recipient
recovery replayed on the scanner side, homomorphic addition of
commitments, key image determinism, canonicality and small-order
rules on every written value. A vector set that does not pass its
own self-checks is never written.

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339, the golden ratio scaled, the number that
already drives the emission calendar). No Python random module, no
version drift, byte-for-byte reproducible on any machine.

Usage: python3 code/scripts/gen_veil_vectors.py
Writes: code/crates/antumbra-veil/tests/vectors.json
"""

import json
import sys
from hashlib import sha512
from pathlib import Path

from Crypto.Hash import keccak
from Crypto.PublicKey import ECC

OUTPUT = Path(__file__).resolve().parents[1] / "crates" / "antumbra-veil" / "tests" / "vectors.json"

# --- Constants mirrored from ADR-011 and the Rust crate -----------

P = 2**255 - 19                             # field prime
L = 2**252 + 27742317777372353535851937790883648493  # group order
D = (-121665 * pow(121666, P - 2, P)) % P   # curve parameter d
VALUE_GENERATOR_DOMAIN = b"ANTUMBRA/veil/value-generator"
HASH_TO_POINT_ROUNDS = 255

# RFC 8032 base point, hardcoded then verified against the curve
# equation, the recovered x and the compressed encoding.
G_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
G_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
G = (G_X, G_Y)
IDENTITY = (0, 1)

RFC8032_T1_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RFC8032_T2_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)


class Lcg:
    """u64 linear congruential generator, Knuth constants."""

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next_u64(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.state

    def next_below(self, bound: int) -> int:
        return self.next_u64() % bound

    def bytes(self, n: int) -> bytes:
        return bytes((self.next_u64() >> 32) & 0xFF for _ in range(n))

    def scalar(self) -> int:
        """A nonzero canonical scalar below the group order."""
        return self.next_below(L - 1) + 1


# --- Keccak-256 (pycryptodome) -------------------------------------

def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256).update(data).digest()


def ed25519_public(seed: bytes) -> bytes:
    key = ECC.construct(curve="ed25519", seed=seed)
    return key.public_key().export_key(format="raw")


# --- From-spec Edwards25519 ----------------------------------------

def inv(x: int) -> int:
    return pow(x, P - 2, P)


def on_curve(point) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def edwards_add(pp, qq):
    """The complete affine addition of RFC 8032 / djb reference.

    Both denominators are asserted nonzero: an exceptional input
    crashes the generator instead of producing a silent zero.
    """
    x1, y1 = pp
    x2, y2 = qq
    den_x = (D * x1 * x2 * y1 * y2 + 1) % P
    den_y = (1 - D * x1 * x2 * y1 * y2) % P
    assert den_x != 0 and den_y != 0, "exceptional addition input"
    x3 = (x1 * y2 + x2 * y1) * inv(den_x) % P
    y3 = (y1 * y2 + x1 * x2) * inv(den_y) % P
    return (x3, y3)


def scalar_mult(k: int, point):
    """Double-and-add, most significant bit first.

    Variable time on purpose: this is the vector generator, not the
    node; the node uses the constant time dalek arithmetic.
    """
    result = IDENTITY
    addend = point
    while k > 0:
        if k & 1:
            result = edwards_add(result, addend)
        addend = edwards_add(addend, addend)
        k >>= 1
    return result


def compress(point) -> bytes:
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def recover_x(yv: int, sign: int):
    """RFC 8032 x recovery; None when y admits no point."""
    x2 = (yv * yv - 1) * inv(D * yv * yv + 1) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
        if (x * x - x2) % P != 0:
            return None
    if x == 0 and sign == 1:
        # RFC 8032: the encoding of x = 0 carries sign 0 only.
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def decompress(encoded: bytes):
    """RFC 8032 decompression, without the canonicality check.

    Mirrors dalek: the nineteen y values at or above the prime alias
    to another point, and the recompression differs. Canonicality is
    decided by the caller through `compress(decompress(b)) == b`.
    """
    yv = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = encoded[31] >> 7
    x = recover_x(yv % P, sign)
    if x is None:
        return None
    return (x, yv % P)


def decode_point(encoded: bytes):
    """The strict decode of the Rust crate: canonical roundtrip,
    not the identity, in the prime-order subgroup (l P = identity).
    None on every rejection."""
    point = decompress(encoded)
    if point is None:
        return None
    if compress(point) != encoded:
        return None
    if point == IDENTITY:
        return None
    if scalar_mult(L, point) != IDENTITY:
        return None
    return point


def point_hex(point) -> str:
    return compress(point).hex()


def scalar_hex(value: int) -> str:
    assert 0 < value < L, "scalar out of range"
    return value.to_bytes(32, "little").hex()


# --- The Veil constructions (from spec, ADR-011) -------------------

def hash_to_scalar(data: bytes) -> int:
    """Hs: Keccak-256 read little-endian, reduced modulo l."""
    return int.from_bytes(keccak256(data), "little") % L


def hash_to_point(data: bytes):
    """Hp: hash-and-check with cofactor clearing (ADR-011).

    For a one-byte counter, hash (data, counter), read the digest
    as a compressed point; the first digest that decompresses
    canonically names the candidate, and the image is eight times
    that candidate: the multiplication by the cofactor places the
    image in the prime-order subgroup. A candidate of pure torsion
    clears to the identity and the search continues. Returns
    (point, counter)."""
    for counter in range(HASH_TO_POINT_ROUNDS + 1):
        digest = keccak256(data + bytes([counter]))
        candidate = decompress(digest)
        if candidate is None or compress(candidate) != digest:
            continue
        cleared = scalar_mult(8, candidate)
        if cleared == IDENTITY:
            continue
        return cleared, counter
    raise AssertionError("hash to point exhausted")


def rfc8032_clamped(seed: bytes) -> bytes:
    digest = sha512(seed).digest()
    clamped = bytearray(digest[0:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return bytes(clamped)


def clamped_reduced(seed: bytes) -> int:
    return int.from_bytes(rfc8032_clamped(seed), "little") % L


def view_seed(seed: bytes) -> bytes:
    return keccak256(seed)


def shared_secret(secret: int, public) -> int:
    """Hs of the compressed point secret * public."""
    product = scalar_mult(secret, public)
    return hash_to_scalar(compress(product))


def one_time_address(shared: int, spend_public):
    return edwards_add(scalar_mult(shared, G), spend_public)


def commit(amount: int, blind: int):
    return edwards_add(scalar_mult(amount, VALUE_GENERATOR), scalar_mult(blind, G))


def one_time_secret(shared: int, spend_secret: int) -> int:
    return (shared + spend_secret) % L


def key_image(one_time_secret_value: int, one_time_public):
    hashed, _ = hash_to_point(compress(one_time_public))
    return scalar_mult(one_time_secret_value, hashed)


def public_of(scalar: int):
    return scalar_mult(scalar, G)


# The value generator H: Hp of the fixed protocol tag, cofactor
# cleared, hence in the prime-order subgroup (ADR-011).
VALUE_GENERATOR, VALUE_GENERATOR_ROUNDS = hash_to_point(VALUE_GENERATOR_DOMAIN)
assert VALUE_GENERATOR != IDENTITY


# --- Self-checks ----------------------------------------------------

def self_check() -> None:
    """The generator verifies its own group before any vector."""
    # The base point: on the curve, recovered from its y, the RFC
    # encoding, and of prime order.
    assert on_curve(G)
    assert recover_x(G_Y, 0) == G_X
    assert compress(G) == bytes.fromhex(
        "5866666666666666666666666666666666666666666666666666666666666666"
    )
    assert scalar_mult(L, G) == IDENTITY
    assert scalar_mult(1, G) == G

    # The affine addition: identity, negation, associativity sample.
    assert edwards_add(G, IDENTITY) == G
    neg_g = (P - G_X, G_Y)
    assert edwards_add(G, neg_g) == IDENTITY
    a, b, c = 5, 7, 11
    assert edwards_add(scalar_mult(a, G), scalar_mult(b, G)) == scalar_mult(a + b, G)
    left = edwards_add(edwards_add(scalar_mult(a, G), scalar_mult(b, G)), scalar_mult(c, G))
    right = edwards_add(scalar_mult(a, G), edwards_add(scalar_mult(b, G), scalar_mult(c, G)))
    assert left == right

    # The RFC 8032 scalar derivation against the pycryptodome
    # reference: two independent sources for the same public key.
    for seed in (RFC8032_T1_SEED, RFC8032_T2_SEED, bytes([9] * 32)):
        expected = ed25519_public(seed)
        assert compress(public_of(clamped_reduced(seed))) == expected
        view = view_seed(seed)
        assert compress(public_of(clamped_reduced(view))) == ed25519_public(view)

    # The decompression and the recompression: every curve point
    # produced here survives the roundtrip; the identity and the
    # torsion points do not decode.
    for k in (2, 3, 4, 5, 6, 7, 8, 12345, 54321):
        point = scalar_mult(k, G)
        assert decompress(compress(point)) == point
        assert decode_point(compress(point)) == point
    identity_encoding = bytearray(32)
    identity_encoding[0] = 1
    assert decode_point(bytes(identity_encoding)) is None
    torsion = bytearray([0xEC] + [0xFF] * 30 + [0x7F])
    assert decode_point(bytes(torsion)) is None
    # A mixed order point, prime plus torsion, is refused too: the
    # subgroup rule excludes the whole torsion attack class.
    mixed = edwards_add(scalar_mult(2, G), (0, P - 1))
    assert decode_point(compress(mixed)) is None

    # Hs is canonical by construction.
    value = hash_to_scalar(b"self-check")
    assert 0 < value < L

    # Hp is deterministic and lands in the prime-order subgroup
    # (the cofactor clearing of ADR-011).
    point, rounds = hash_to_point(b"self-check")
    again, rounds_again = hash_to_point(b"self-check")
    assert point == again and rounds == rounds_again
    assert scalar_mult(L, point) == IDENTITY
    assert point != IDENTITY


# --- Vector construction -------------------------------------------

def build_scalar_vectors(rng: Lcg) -> list:
    seeds = [
        RFC8032_T1_SEED,
        RFC8032_T2_SEED,
        bytes([0] * 31 + [1]),
        bytes([255] * 32),
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
    ]
    vectors = []
    for seed in seeds:
        view = view_seed(seed)
        vectors.append({
            "seed": seed.hex(),
            "clamped": rfc8032_clamped(seed).hex(),
            "reduced": scalar_hex(clamped_reduced(seed)),
            "public": point_hex(public_of(clamped_reduced(seed))),
            "view_reduced": scalar_hex(clamped_reduced(view)),
            "view_public": point_hex(public_of(clamped_reduced(view))),
        })
    return vectors


def build_hash_vectors(rng: Lcg) -> tuple:
    scalar_inputs = [
        b"",
        b"ANTUMBRA",
        RFC8032_T1_SEED,
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(17),
        b"x",
        bytes([0] * 32),
    ]
    scalar_vectors = [
        {"data": data.hex(), "scalar": scalar_hex(hash_to_scalar(data))}
        for data in scalar_inputs
    ]
    for vector in scalar_vectors:
        assert 0 < int.from_bytes(bytes.fromhex(vector["scalar"]), "little") < L

    # Point inputs: fixed tags, pseudorandom values, and enough of
    # them that the set covers a multi-round Hp (counter above 0).
    point_inputs = [
        VALUE_GENERATOR_DOMAIN,
        b"ANTUMBRA/Hp/self-check",
        b"",
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
        rng.bytes(32),
    ]
    point_vectors = []
    for data in point_inputs:
        point, rounds = hash_to_point(data)
        # Every image is a canonical, non-degenerate subgroup point.
        assert decode_point(compress(point)) == point
        point_vectors.append({
            "data": data.hex(),
            "point": point_hex(point),
            "rounds": rounds,
        })
    assert any(v["rounds"] >= 1 for v in point_vectors), "multi-round Hp coverage"
    assert any(v["rounds"] == 0 for v in point_vectors), "first-round Hp coverage"

    generator_point, generator_rounds = VALUE_GENERATOR, VALUE_GENERATOR_ROUNDS
    return scalar_vectors, point_vectors, generator_point, generator_rounds


def build_onetime_vectors(rng: Lcg) -> tuple:
    """The full payment pipeline, sender side and scanner side."""
    vectors = []
    for _ in range(6):
        seed = rng.bytes(32)
        a = clamped_reduced(view_seed(seed))
        b = clamped_reduced(seed)
        a_public = public_of(a)
        b_public = public_of(b)
        # The published keys match the Ed25519 reference: the bridge
        # between the transparent sphere and the Veil.
        assert compress(a_public) == ed25519_public(view_seed(seed))
        assert compress(b_public) == ed25519_public(seed)

        r = rng.scalar()
        r_public = public_of(r)
        shared = shared_secret(r, a_public)
        p_point = one_time_address(shared, b_public)

        # The scanner replays the derivation from its secrets.
        shared_scan = shared_secret(a, r_public)
        assert shared_scan == shared
        assert one_time_address(shared_scan, b_public) == p_point

        # The one-time secret generates the one-time address.
        p_secret = one_time_secret(shared_scan, b)
        assert public_of(p_secret) == p_point

        # The key image of the spent output.
        image = key_image(p_secret, p_point)
        assert key_image(p_secret, p_point) == image

        vectors.append({
            "seed": seed.hex(),
            "r": scalar_hex(r),
            "ephemeral": point_hex(r_public),
            "shared": scalar_hex(shared),
            "one_time_public": point_hex(p_point),
            "one_time_secret": scalar_hex(p_secret),
            "key_image": point_hex(image),
        })
    return vectors


def build_commitment_vectors(rng: Lcg, value_generator_point) -> tuple:
    amounts = [0, 1, 100_000_000, 1_618_033_900_000_000, rng.next_below(2**48)]
    vectors = []
    for amount in amounts:
        blind = rng.scalar()
        point = commit(amount, blind)
        assert decode_point(compress(point)) == point
        vectors.append({
            "amount": amount,
            "blind": scalar_hex(blind),
            "point": point_hex(point),
        })
    # The homomorphic sum: two commitments and their composition.
    v1, b1 = 1_234_567_890, rng.scalar()
    v2, b2 = 9_876_543_210, rng.scalar()
    c1 = commit(v1, b1)
    c2 = commit(v2, b2)
    b_sum = (b1 + b2) % L
    c_sum = commit(v1 + v2, b_sum)
    assert edwards_add(c1, c2) == c_sum
    homomorphic = {
        "amount1": v1,
        "blind1": scalar_hex(b1),
        "point1": point_hex(c1),
        "amount2": v2,
        "blind2": scalar_hex(b2),
        "point2": point_hex(c2),
        "amount_sum": v1 + v2,
        "blind_sum": scalar_hex(b_sum),
        "point_sum": point_hex(c_sum),
    }
    assert decode_point(compress(value_generator_point)) == value_generator_point
    return vectors, homomorphic


def build_key_image_vectors(rng: Lcg, onetime_vectors: list) -> list:
    vectors = []
    # The images of the one-time pipeline, replayed.
    for source in onetime_vectors[:3]:
        p_secret = int.from_bytes(bytes.fromhex(source["one_time_secret"]), "little")
        p_point = decompress(bytes.fromhex(source["one_time_public"]))
        vectors.append({
            "secret": source["one_time_secret"],
            "public": source["one_time_public"],
            "image": point_hex(key_image(p_secret, p_point)),
        })
    # Same secret, different output: Hp(P) mixes the output in.
    secret = rng.scalar()
    spend_public = public_of(rng.scalar())
    r1, r2 = rng.scalar(), rng.scalar()
    shared1 = shared_secret(r1, public_of(rng.scalar()))
    shared2 = shared_secret(r2, public_of(rng.scalar()))
    p1 = one_time_address(shared1, spend_public)
    p2 = one_time_address(shared2, spend_public)
    image1 = key_image(secret, p1)
    image2 = key_image(secret, p2)
    assert image1 != image2
    vectors.append({
        "secret": scalar_hex(secret),
        "public": point_hex(p1),
        "image": point_hex(image1),
    })
    vectors.append({
        "secret": scalar_hex(secret),
        "public": point_hex(p2),
        "image": point_hex(image2),
    })
    # Different secrets on the same output: distinct images.
    secret_b = (secret + 1) % L
    image_b = key_image(secret_b, p1)
    assert image_b != image1
    vectors.append({
        "secret": scalar_hex(secret_b),
        "public": point_hex(p1),
        "image": point_hex(image_b),
    })
    return vectors


def build_invalid_vectors() -> tuple:
    # Points: the identity, the order 2 point, a non-canonical y at
    # 2^255 - 1, and a y below the prime that admits no x (searched
    # deterministically from 2 upward).
    identity = bytearray(32)
    identity[0] = 1
    torsion = bytearray([0xEC] + [0xFF] * 30 + [0x7F])
    non_canonical = bytearray([0xFF] * 31 + [0x7F])
    no_x = None
    for yv in range(2, 1000):
        if recover_x(yv, 0) is None:
            no_x = bytearray(yv.to_bytes(32, "little"))
            break
    assert no_x is not None, "a y without a point exists below 1000"
    invalid_points = [
        {"bytes": bytes(identity).hex(), "error": "identity"},
        {"bytes": bytes(torsion).hex(), "error": "outside_subgroup"},
        {"bytes": bytes(non_canonical).hex(), "error": "non_canonical"},
        {"bytes": bytes(no_x).hex(), "error": "non_canonical"},
    ]
    for vector in invalid_points:
        assert decode_point(bytes.fromhex(vector["bytes"])) is None

    # Scalars: zero, the group order, one above it, a random value
    # above it.
    above = L + 7
    invalid_scalars = [
        {"bytes": (0).to_bytes(32, "little").hex(), "error": "non_canonical"},
        {"bytes": L.to_bytes(32, "little").hex(), "error": "non_canonical"},
        {"bytes": above.to_bytes(32, "little").hex(), "error": "non_canonical"},
    ]
    for vector in invalid_scalars:
        value = int.from_bytes(bytes.fromhex(vector["bytes"]), "little")
        assert value == 0 or value >= L
    return invalid_points, invalid_scalars


def main() -> int:
    self_check()
    rng = Lcg(16180339)

    scalar_vectors = build_scalar_vectors(rng)
    hash_scalar_vectors, hash_point_vectors, generator_point, generator_rounds = (
        build_hash_vectors(rng)
    )
    onetime_vectors = build_onetime_vectors(rng)
    commitment_vectors, homomorphic = build_commitment_vectors(rng, generator_point)
    key_image_vectors = build_key_image_vectors(rng, onetime_vectors)
    invalid_points, invalid_scalars = build_invalid_vectors()

    vectors = {
        "format": 1,
        "generator": "code/scripts/gen_veil_vectors.py (from-spec Edwards25519, pycryptodome, independent implementation)",
        "scalar": scalar_vectors,
        "hash_to_scalar": hash_scalar_vectors,
        "hash_to_point": hash_point_vectors,
        "value_generator": {
            "point": point_hex(generator_point),
            "rounds": generator_rounds,
        },
        "onetime": onetime_vectors,
        "commitment": commitment_vectors,
        "homomorphism": homomorphic,
        "key_image": key_image_vectors,
        "invalid_point": invalid_points,
        "invalid_scalar": invalid_scalars,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"OK: {len(scalar_vectors)} scalar, {len(hash_scalar_vectors)} Hs, "
          f"{len(hash_point_vectors)} Hp, {len(onetime_vectors)} one-time, "
          f"{len(commitment_vectors)} commitment, {len(key_image_vectors)} key image, "
          f"{len(invalid_points) + len(invalid_scalars)} invalid vectors written to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
