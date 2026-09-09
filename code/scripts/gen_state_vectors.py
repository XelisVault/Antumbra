#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-state.

Independent re-implementation of every output-producing routine
of the state layer (ADR-024, ADR-026): the emission calendar (the
Lucas-Fibonacci closed form of floor(E0 * R^n), the per-slot
reward spread, the treasury share and window), the devnet
treasury address, the coinbase rules, and the UTXO ledger itself
(existence, unspentness, double-spend resolution by order, the
key binding of an input to the spend key of the output's
address, conservation, maturity, the atomic apply of a block,
the rebuild of a reorganized order). Keccak-256 and Ed25519 come
from pycryptodome; the calendar, the codec and the ledger are
re-implemented from the ADR text alone. The output is the
archived vector set consumed by the Rust test suite: both
implementations must agree bit for bit (CONTRIBUTING.md,
verification layer 1).

The generator also decodes: a Python reader mirrors the strict
canonical transaction decoding, and every generated transaction
must survive encode-decode-encode unchanged. Every apply case
replays the full rule battery in the Python ledger, then the
self-checks assert the invariants the ADR states: the calendar
closes on the cap, each eclipse closes on its emission, the
ledger conserves created = spent + emitted after every case, and
a rejected block leaves the ledger exactly where it stood. A
vector set that does not pass its own self-checks is never
written.

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339, the golden ratio scaled, the number
that already drives the emission calendar). No Python random
module, no version drift, byte-for-byte reproducible on any
machine.

Usage: python3 code/scripts/gen_state_vectors.py
Writes: code/crates/antumbra-state/tests/vectors.json
"""

import json
import sys
from math import isqrt
from pathlib import Path

from Crypto.Hash import keccak
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "crates"
    / "antumbra-state"
    / "tests"
    / "vectors.json"
)

# --- Constants mirrored from ADR-024 and the Rust crate ----------

VERSION_1 = 1
TAG_TRANSFER = 0
TAG_COINBASE = 6
MAX_INPUTS = 64
MAX_OUTPUTS = 32
MAX_EXTRA_LEN = 512

CAP_ATOMIC = 16_180_339 * 100_000_000
BLOCKS_PER_ECLIPSE = 63_115_200
ECLIPSES = 34
E0_ATU = 6_180_340
TREASURY_NUMERATOR = 618
TREASURY_DENOMINATOR = 10_000
TREASURY_ECLIPSES = 8
MATURITY = 10
DEVNET_PREFIX = 0x44  # b'D'
U64_MAX = 0xFFFFFFFFFFFFFFFF

SEED = 16_180_339


# --- Deterministic primitives ------------------------------------

class Lcg:
    """The fixed-seed generator of every archived vector set."""

    def __init__(self, seed: int):
        self.state = seed & U64_MAX

    def next_u64(self) -> int:
        # Numerical Recipes constants, same as the other generators.
        self.state = (6_364_136_223_846_793_005 * self.state + 1) & U64_MAX
        return self.state

    def next_below(self, bound: int) -> int:
        return self.next_u64() % bound

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += self.next_u64().to_bytes(8, "little")
        return bytes(out[:n])


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def ed25519_public(seed: bytes) -> bytes:
    key = ECC.construct(curve="ed25519", seed=seed)
    return key.public_key().export_key(format="raw")


def write_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append(0x80 | (value & 0x7F))
        value >>= 7
    out.append(value)
    return bytes(out)


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while True:
        if pos >= len(data):
            raise ValueError("varint runs past the end")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift > 56:
            raise ValueError("varint too long")


def view_seed_of(spend_seed: bytes) -> bytes:
    return keccak256(spend_seed)


def address_raw(prefix: int, spend: bytes, view: bytes) -> bytes:
    checksummed = bytes([prefix]) + spend + view
    return checksummed + keccak256(checksummed)[:4]


# --- The transaction codec (Transfer and Coinbase) ----------------


class Tx:
    """A canonical transaction: the Python mirror of antumbra-tx."""

    def __init__(self, tx_type: int, fee: int, inputs: list, outputs: list, extra: bytes):
        self.tx_type = tx_type
        self.fee = fee
        self.inputs = inputs  # list of dicts: tx, index, key, signature
        self.outputs = outputs  # list of dicts: address(bytes69), amount
        self.extra = extra

    def encode(self) -> bytes:
        out = bytearray()
        out += VERSION_1.to_bytes(2, "little")
        out.append(self.tx_type)
        out += self.fee.to_bytes(8, "little")
        out += write_varint(len(self.inputs))
        for i in self.inputs:
            out += i["tx"]
            out += i["index"].to_bytes(4, "little")
            out += i["key"]
            out += i["signature"]
        out += write_varint(len(self.outputs))
        for o in self.outputs:
            out += o["address"]
            out += o["amount"].to_bytes(8, "little")
        out += write_varint(len(self.extra))
        out += self.extra
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "Tx":
        pos = 0
        if len(data) < 12:
            raise ValueError("short transaction")
        version = int.from_bytes(data[0:2], "little")
        if version != VERSION_1:
            raise ValueError("version")
        tx_type = data[2]
        if tx_type not in (TAG_TRANSFER, TAG_COINBASE):
            raise ValueError("type tag")
        fee = int.from_bytes(data[3:11], "little")
        pos = 11
        count, pos = read_varint(data, pos)
        if count > MAX_INPUTS:
            raise ValueError("inputs")
        inputs = []
        for _ in range(count):
            tx = data[pos : pos + 32]
            index = int.from_bytes(data[pos + 32 : pos + 36], "little")
            key = data[pos + 36 : pos + 68]
            signature = data[pos + 68 : pos + 132]
            if len(signature) != 64:
                raise ValueError("input")
            pos += 132
            inputs.append(
                {"tx": tx, "index": index, "key": key, "signature": signature}
            )
        count, pos = read_varint(data, pos)
        if count > MAX_OUTPUTS:
            raise ValueError("outputs")
        outputs = []
        for _ in range(count):
            address = data[pos : pos + 69]
            amount = int.from_bytes(data[pos + 69 : pos + 77], "little")
            if len(address) != 69:
                raise ValueError("output")
            pos += 77
            outputs.append({"address": address, "amount": amount})
        length, pos = read_varint(data, pos)
        extra = data[pos : pos + length]
        pos += length
        if pos != len(data):
            raise ValueError("trailing bytes")
        return cls(tx_type, fee, inputs, outputs, extra)

    def tx_id(self) -> bytes:
        return keccak256(self.encode())


def make_transfer(inputs, outputs, fee, extra=b"") -> Tx:
    return Tx(TAG_TRANSFER, fee, inputs, outputs, extra)


def make_coinbase(height: int, outputs) -> Tx:
    return Tx(TAG_COINBASE, 0, [], outputs, height.to_bytes(8, "little"))


def unsigned_input(tx_hash: bytes, index: int, key: bytes) -> dict:
    return {"tx": tx_hash, "index": index, "key": key, "signature": bytes(64)}


def output(address: bytes, amount: int) -> dict:
    return {"address": address, "amount": amount}


# --- The emission calendar, independently ------------------------


def fibonacci_lucas(n: int) -> tuple[int, int]:
    """(F(n), L(n)) by iteration, from the ADR text alone."""
    f_prev, f_curr = 0, 1
    l_prev, l_curr = 2, 1
    if n == 0:
        return f_prev, l_prev
    for _ in range(1, n):
        f_prev, f_curr = f_curr, f_prev + f_curr
        l_prev, l_curr = l_curr, l_prev + l_curr
    return f_curr, l_curr


def exact_eclipse_emission(n: int) -> int:
    """floor(E0 * R^n) exactly, R = (sqrt(5) - 1) / 2.

    R = |psi| with psi the conjugate of phi, and
    psi^n = (L(n) - sqrt(5) F(n)) / 2. The floor of
    (P + Q sqrt(5)) / 2 over integers is
    (P + isqrt(5 Q^2)) / 2 when Q > 0 and (S - 1) / 2 with
    S = P - isqrt(5 Q^2) when Q < 0: the one-unit correction of
    the negative irrational part.
    """
    if n == 0:
        return E0_ATU
    fib, lucas = fibonacci_lucas(n)
    if n % 2 == 0:
        p, q = E0_ATU * lucas, -(E0_ATU * fib)
    else:
        p, q = -(E0_ATU * lucas), E0_ATU * fib
    root = isqrt(5 * q * q)
    if q > 0:
        return (p + root) // 2
    return (p - root - 1) // 2


def eclipse_emissions_atu() -> list[int]:
    """The archived calendar: 33 closed-form eclipses, the 34th
    absorbing the remainder to the cap."""
    emissions = [exact_eclipse_emission(n) for n in range(33)]
    emissions.append(16_180_339 - sum(emissions))
    assert sum(emissions) == 16_180_339, "the calendar does not close on the cap"
    return emissions


ECLIPSE_EMISSIONS = eclipse_emissions_atu()


def reward_of_slot(slot: int) -> int:
    if slot == 0:
        return 0
    eclipse = (slot - 1) // BLOCKS_PER_ECLIPSE
    emission_atomic = ECLIPSE_EMISSIONS[eclipse] * 100_000_000
    base = emission_atomic // BLOCKS_PER_ECLIPSE
    remainder = emission_atomic % BLOCKS_PER_ECLIPSE
    position = (slot - 1) % BLOCKS_PER_ECLIPSE
    return base + (1 if position < remainder else 0)


def treasury_share_of(reward_atomic: int) -> int:
    return reward_atomic * TREASURY_NUMERATOR // TREASURY_DENOMINATOR


def treasury_active_at_slot(slot: int) -> bool:
    return slot >= 1 and (slot - 1) // BLOCKS_PER_ECLIPSE < TREASURY_ECLIPSES


def expected_coinbase(slot: int, block_fees: int) -> tuple[int, int, int]:
    """(output_count, treasury_amount, total) for the slot."""
    reward = reward_of_slot(slot)
    total = reward + block_fees
    if treasury_active_at_slot(slot):
        return 2, treasury_share_of(reward), total
    return 1, 0, total


def devnet_treasury_address() -> bytes:
    spend = ed25519_public(keccak256(b"antumbra-treasury-spend-devnet"))
    view = ed25519_public(keccak256(b"antumbra-treasury-view-devnet"))
    return address_raw(DEVNET_PREFIX, spend, view)


TREASURY_ADDRESS = devnet_treasury_address()


# --- The Python ledger: the mirror of antumbra-state --------------


class BlockPayload:
    def __init__(self, height: int, txs: list):
        self.height = height
        self.txs = txs


class StateError(Exception):
    """The named rules of the ledger; the name is the wire form."""

    def __init__(self, name: str, detail: str = ""):
        super().__init__(f"{name}: {detail}")
        self.name = name
        self.detail = detail


class Ledger:
    """The independent Python ledger of ADR-024."""

    def __init__(self):
        self.utxos = {}  # (tx_id, index) -> (address, amount, coinbase_slot|None)
        self.spent = set()  # (tx_id, index)
        self.applied = 0
        self.created = 0
        self.spent_value = 0
        self.emitted = 0

    def apply_order(self, order: list, fetch) -> None:
        first = True
        for block_id in order:
            payload = fetch(block_id)
            if payload is None:
                raise StateError("MissingPayload", block_id.hex()[:16])
            if first:
                first = False
                if payload.height != 0:
                    raise StateError("NotGenesis", str(payload.height))
                if payload.txs:
                    raise StateError("GenesisPayload", str(len(payload.txs)))
                self.applied = 1
                continue
            self.apply_block(payload.height, payload.txs)

    def apply_block(self, height: int, txs: list) -> None:
        slot = self.applied
        # The pure phase over a scratch overlay.
        new_outputs = {}
        spent_refs = set()
        spent_value = 0

        ids = [t.tx_id() for t in txs]
        for a, b in zip(ids, ids[1:]):
            if a >= b:
                raise StateError("UnsortedPayload")

        if height == 0:
            if txs:
                raise StateError("GenesisPayload", str(len(txs)))
            return

        coinbases = [t for t in txs if t.tx_type == TAG_COINBASE]
        if len(coinbases) != 1:
            raise StateError("CoinbaseCount", str(len(coinbases)))

        fees = sum(t.fee for t in txs if t.tx_type != TAG_COINBASE)

        for tx in txs:
            if tx.tx_type == TAG_COINBASE:
                self._validate_coinbase(tx, slot, height, fees)
            else:
                spent_value = self._validate_transfer(
                    tx, slot, new_outputs, spent_refs, spent_value
                )

        # The commit phase: nothing can fail.
        for tx in txs:
            tx_id = tx.tx_id()
            for index, o in enumerate(tx.outputs):
                self.utxos[(tx_id, index)] = (
                    o["address"],
                    o["amount"],
                    slot if tx.tx_type == TAG_COINBASE else None,
                )
                self.created += o["amount"]
            if tx.tx_type == TAG_COINBASE:
                self.emitted += reward_of_slot(slot)
        for ref in spent_refs:
            del self.utxos[ref]
            self.spent.add(ref)
        self.spent_value += spent_value
        self.applied += 1

    def _validate_coinbase(self, tx: Tx, slot: int, height: int, fees: int) -> None:
        if tx.inputs:
            raise StateError("CoinbaseInputs", str(len(tx.inputs)))
        if tx.fee != 0:
            raise StateError("CoinbaseFee")
        if len(tx.extra) != 8:
            raise StateError("CoinbaseExtra", str(len(tx.extra)))
        declared = int.from_bytes(tx.extra, "little")
        if declared != height:
            raise StateError("CoinbaseHeight", f"{declared} in block {height}")
        count, treasury_amount, total = expected_coinbase(slot, fees)
        if len(tx.outputs) != count:
            raise StateError(
                "CoinbaseOutputs", f"expected {count}, found {len(tx.outputs)}"
            )
        found = sum(o["amount"] for o in tx.outputs)
        if found != total:
            raise StateError("CoinbaseValue", f"expected {total}, found {found}")
        if count == 2:
            if tx.outputs[1]["address"] != TREASURY_ADDRESS:
                raise StateError("CoinbaseTreasuryAddress")
            if tx.outputs[1]["amount"] != treasury_amount:
                raise StateError(
                    "CoinbaseTreasuryShare",
                    f"expected {treasury_amount}, found {tx.outputs[1]['amount']}",
                )

    def _validate_transfer(
        self, tx: Tx, slot: int, new_outputs: dict, spent_refs: set, spent_value: int
    ) -> int:
        if not tx.inputs:
            raise StateError("NoInputs")
        input_value = 0
        for i in tx.inputs:
            ref = (i["tx"], i["index"])
            entry = self.utxos.get(ref) or new_outputs.get(ref)
            if entry is None:
                if ref in self.spent or ref in spent_refs:
                    raise StateError("DoubleSpend", ref_text(ref))
                raise StateError("UnknownOutput", ref_text(ref))
            if ref in spent_refs:
                raise StateError("DoubleSpend", ref_text(ref))
            address, amount, coinbase_slot = entry
            # The key binding (ADR-026): the claimed key must be the
            # spend key of the output's address (bytes 1..33 of the
            # raw form). Ownership before the clock: a reference
            # both unbound and immature names the binding.
            if i["key"] != address[1:33]:
                raise StateError("KeyNotBound", ref_text(ref))
            if coinbase_slot is not None and slot < coinbase_slot + MATURITY:
                raise StateError(
                    "ImmatureCoinbase",
                    f"{ref_text(ref)} of slot {coinbase_slot} at slot {slot}",
                )
            input_value += amount
            spent_refs.add(ref)
        output_value = tx.fee + sum(o["amount"] for o in tx.outputs)
        if input_value != output_value:
            raise StateError(
                "Conservation", f"expected {input_value}, found {output_value}"
            )
        tx_id = tx.tx_id()
        for index, o in enumerate(tx.outputs):
            ref = (tx_id, index)
            if ref in self.utxos or ref in new_outputs or ref in self.spent:
                raise StateError("OutputCollision", ref_text(ref))
            new_outputs[ref] = (o["address"], o["amount"], None)
        return spent_value + input_value

    def snapshot(self) -> list:
        return [
            {
                "tx": ref[0].hex(),
                "index": ref[1],
                "address": entry[0].hex(),
                "amount": entry[1],
                "coinbase_slot": entry[2],
            }
            for ref, entry in sorted(self.utxos.items())
        ]

    def stats(self) -> dict:
        return {
            "applied": self.applied,
            "created": self.created,
            "spent_value": self.spent_value,
            "emitted": self.emitted,
            "utxos": len(self.utxos),
        }


def ref_text(ref) -> str:
    return f"{ref[0].hex()[:16]}:{ref[1]}"


# --- Vector construction ------------------------------------------

lcg = Lcg(SEED)


def random_seed_bytes() -> bytes:
    return lcg.bytes(32)


def random_address() -> bytes:
    seed = random_seed_bytes()
    spend = ed25519_public(seed)
    view = ed25519_public(view_seed_of(seed))
    return address_raw(DEVNET_PREFIX, spend, view)


# The spend public key of every address the generator constructs
# honestly: an input that spends an output of one of these parties
# claims the recorded key (ADR-026). Addresses built for the wrong
# side of a rejection (a foreign treasury, a thief's destination)
# stay unregistered: no honest input ever claims them.
SPEND_KEYS: dict = {}


def owned_address() -> bytes:
    """A random address whose spend key the generator records."""
    seed = random_seed_bytes()
    spend = ed25519_public(seed)
    view = ed25519_public(view_seed_of(seed))
    address = address_raw(DEVNET_PREFIX, spend, view)
    SPEND_KEYS[address] = spend
    return address


def spend_key_of(address: bytes) -> bytes:
    """The recorded spend key of an owned address."""
    key = SPEND_KEYS.get(address)
    assert key is not None, "the address is not an owned party"
    return key


def thief_destination(thief_seed: bytes) -> bytes:
    """The thief's own address: unregistered, spendable only by
    the thief — which is exactly what the binding refuses."""
    return address_raw(
        DEVNET_PREFIX,
        ed25519_public(thief_seed),
        ed25519_public(view_seed_of(thief_seed)),
    )


def signed_thief_transfer(
    tx_hash: bytes, index: int, thief_seed: bytes, destination: bytes, amount: int, fee: int
) -> Tx:
    """A one-input theft, correctly signed by the thief.

    The signature is real: it verifies against the claimed key. The
    point of the vector is that the ledger refuses the block anyway
    - the claimed key is not the spend key of the output's
    address, and no signature, however valid, changes that.
    """
    inputs = [unsigned_input(tx_hash, index, ed25519_public(thief_seed))]
    theft = make_transfer(inputs, [output(destination, amount)], fee)
    # The signing message: the canonical encoding with every
    # signature zeroed, exactly as the transaction layer defines
    # it (the inputs above are unsigned, so the encoding is the
    # message).
    message = theft.encode()
    key = ECC.construct(curve="ed25519", seed=thief_seed)
    theft.inputs[0]["signature"] = eddsa.new(key, mode="rfc8032").sign(message)
    return theft


def random_key() -> bytes:
    return ed25519_public(random_seed_bytes())


def build_coinbase(slot: int, height: int, fees: int, miner_address: bytes, mutate=None):
    """A canonical coinbase, with optional single-rule mutations."""
    count, treasury_amount, total = expected_coinbase(slot, fees)
    outputs = []
    miner_amount = total - (treasury_amount if count == 2 else 0)
    if mutate == "treasury_address":
        outputs.append(output(miner_address, miner_amount))
        outputs.append(output(random_address(), treasury_amount))
    elif mutate == "treasury_share":
        # The total stays exact, the split drifts by one atom: the
        # share rule fires, not the value rule.
        outputs.append(output(miner_address, miner_amount - 1))
        outputs.append(output(TREASURY_ADDRESS, treasury_amount + 1))
    elif mutate == "value":
        outputs.append(output(miner_address, miner_amount + 1))
        if count == 2:
            outputs.append(output(TREASURY_ADDRESS, treasury_amount))
    elif mutate == "outputs":
        outputs.append(output(miner_address, miner_amount))
        if count == 2:
            outputs.append(output(TREASURY_ADDRESS, treasury_amount))
        outputs.append(output(random_address(), 1))
    elif mutate == "inputs":
        # The caller replaces the empty input list afterwards.
        outputs.append(output(miner_address, miner_amount))
        if count == 2:
            outputs.append(output(TREASURY_ADDRESS, treasury_amount))
    elif mutate == "fee":
        outputs.append(output(miner_address, miner_amount))
        if count == 2:
            outputs.append(output(TREASURY_ADDRESS, treasury_amount))
    else:
        outputs.append(output(miner_address, miner_amount))
        if count == 2:
            outputs.append(output(TREASURY_ADDRESS, treasury_amount))

    if mutate == "height":
        tx = make_coinbase(height + 1, outputs)
    elif mutate == "extra":
        tx = Tx(TAG_COINBASE, 0, [], outputs, (height).to_bytes(7, "little"))
    else:
        tx = make_coinbase(height, outputs)
    if mutate == "fee":
        tx.fee = 1
    if mutate == "inputs":
        tx.inputs = [unsigned_input(keccak256(b"nowhere"), 0, random_key())]
    return tx


def block_id_of(name: str, index: int) -> bytes:
    return keccak256(f"state-vector-{name}-{index}".encode())


def sort_payload(txs: list) -> list:
    return sorted(txs, key=lambda t: t.tx_id())


def encode_blocks(blocks: list) -> list:
    """[{height, txs: [canonical hex]}], ids ascending."""
    return [
        {"height": b["height"], "txs": [t.encode().hex() for t in b["txs"]]}
        for b in blocks
    ]


def linear_chain(name: str, block_builders: list) -> dict:
    """A linear chain: the order is the block list; ids are derived
    from the name and the position, and the fetch is a closure over
    the list."""
    blocks = [{"height": 0, "txs": []}]
    for index, build in enumerate(block_builders, start=1):
        blocks.append({"height": index, "txs": sort_payload(build(index))})
    order = [block_id_of(name, i) for i in range(len(blocks))]
    by_id = {block_id_of(name, i): blocks[i] for i in range(len(blocks))}
    return {"blocks": blocks, "order": order, "by_id": by_id}


def fetch_of(by_id: dict):
    def fetch(block_id: bytes):
        block = by_id.get(block_id)
        if block is None:
            return None
        return BlockPayload(block["height"], block["txs"])

    return fetch


def apply_and_snapshot(case: dict) -> dict:
    ledger = Ledger()
    ledger.apply_order(case["order"], fetch_of(case["by_id"]))
    stats = ledger.stats()
    assert stats["created"] == stats["spent_value"] + stats["emitted"], (
        f"{case.get('name', 'case')} does not conserve"
    )
    return {"stats": stats, "utxos": ledger.snapshot()}


# --- Case 1: the plain chain, coinbases then chained transfers ----

MINER_A = owned_address()
MINER_B = owned_address()
ALICE = owned_address()
BOB = owned_address()
CAROL = owned_address()


def resolve_chain_1():
    """Builds the chain with the actual coinbase ids of earlier
    blocks available to later transfers."""
    blocks = [{"height": 0, "txs": []}]
    miner_outputs = {}  # height -> (tx_id, amount)
    for height in range(1, 13):
        coinbase = build_coinbase(height, height, 0, MINER_A)
        blocks.append({"height": height, "txs": sort_payload([coinbase])})
        miner_outputs[height] = (coinbase.tx_id(), coinbase.outputs[0]["amount"])

    # Block 13: spends the miner output of block 3 (slot 3, maturity
    # at slot 13), pays Alice and Bob, one atom of fee.
    tx_id_3, amount_3 = miner_outputs[3]
    fee = 1
    transfer = make_transfer(
        [unsigned_input(tx_id_3, 0, spend_key_of(MINER_A))],
        [output(ALICE, amount_3 // 2), output(BOB, amount_3 - amount_3 // 2 - fee)],
        fee,
    )
    coinbase = build_coinbase(13, 13, fee, MINER_B)
    blocks.append({"height": 13, "txs": sort_payload([coinbase, transfer])})

    # Block 14: spends Alice's output of block 13 (no maturity for
    # transfer outputs), pays Carol, two atoms of fee.
    alice_out = transfer.tx_id(), transfer.outputs[0]["amount"]
    fee2 = 2
    transfer2 = make_transfer(
        [unsigned_input(alice_out[0], 0, spend_key_of(ALICE))],
        [output(CAROL, alice_out[1] - fee2)],
        fee2,
    )
    coinbase = build_coinbase(14, 14, fee2, MINER_B)
    blocks.append({"height": 14, "txs": sort_payload([coinbase, transfer2])})

    # Block 15: two chained transfers in one block: the first spends
    # Bob's output of block 13, the second spends an output the
    # first creates (same-block chaining).
    bob_out = transfer.tx_id(), transfer.outputs[1]["amount"]
    fee3 = 3
    t1 = make_transfer(
        [unsigned_input(bob_out[0], 1, spend_key_of(BOB))],
        [output(ALICE, bob_out[1] - fee3 - 5), output(BOB, 5)],
        fee3,
    )
    t2 = make_transfer(
        [unsigned_input(t1.tx_id(), 0, spend_key_of(ALICE))],
        [output(CAROL, t1.outputs[0]["amount"] - 1)],
        1,
    )
    t1, t2 = ensure_id_order(t1, t2)
    coinbase = build_coinbase(15, 15, fee3 + 1, MINER_A)
    blocks.append({"height": 15, "txs": sort_payload([coinbase, t1, t2])})
    return blocks


def ensure_id_order(t1: Tx, t2: Tx) -> tuple[Tx, Tx]:
    """Same-block chaining requires the spender to sort after the
    creator: the payload order is the id order. Retries with a
    deterministic extra byte until the pair is ordered."""
    attempt = 0
    while not (t1.tx_id() < t2.tx_id()):
        attempt += 1
        t2.extra = bytes([attempt])
    return t1, t2


def coinbase_only_prefix(name: str, length: int, miner: bytes) -> dict:
    """A linear chain of coinbase-only blocks: the shared prefix of
    the rejection cases and the reorg."""
    blocks = [{"height": 0, "txs": []}]
    for height in range(1, length + 1):
        coinbase = build_coinbase(height, height, 0, miner)
        blocks.append({"height": height, "txs": sort_payload([coinbase])})
    order = [block_id_of(name, i) for i in range(len(blocks))]
    by_id = {block_id_of(name, i): blocks[i] for i in range(len(blocks))}
    return {"blocks": blocks, "order": order, "by_id": by_id, "name": name}


def miner_output_of(prefix: dict, height: int):
    """The miner output (tx id, amount) of a coinbase-only block."""
    block = prefix["blocks"][height]
    coinbase = block["txs"][0]
    return coinbase.tx_id(), coinbase.outputs[0]["amount"]


def reject_case(name: str, prefix_length: int, build_bad, expect=None) -> dict:
    """A valid coinbase-only prefix, then one bad block: the apply
    fails, the ledger stands at the prefix."""
    prefix = coinbase_only_prefix(name, prefix_length, MINER_A)
    bad_height = prefix_length + 1
    txs = build_bad(prefix, bad_height)
    bad_block = {"height": bad_height, "txs": txs}
    blocks = prefix["blocks"] + [bad_block]
    order = [block_id_of(name, i) for i in range(len(blocks))]
    by_id = {block_id_of(name, i): blocks[i] for i in range(len(blocks))}

    # The Python ledger must fail with the expected name, and stand
    # at the prefix state.
    ledger = Ledger()
    error = None
    try:
        ledger.apply_order(order, fetch_of(by_id))
    except StateError as e:
        error = e.name
    assert error is not None, f"reject case {name} was accepted"
    if expect is not None:
        assert error == expect, (
            f"reject case {name} fired {error}, expected {expect}"
        )
    good = Ledger()
    good.apply_order(prefix["order"], fetch_of(prefix["by_id"]))
    assert ledger.snapshot() == good.snapshot(), (
        f"reject case {name} mutated the ledger"
    )
    return {
        "name": name,
        "blocks": encode_blocks(blocks),
        "order": [b.hex() for b in order],
        "error": error,
        "after_reject": {"stats": ledger.stats(), "utxos": ledger.snapshot()},
    }


def apply_case(name: str, blocks: list) -> dict:
    order = [block_id_of(name, i) for i in range(len(blocks))]
    by_id = {block_id_of(name, i): blocks[i] for i in range(len(blocks))}
    case = {"blocks": blocks, "order": order, "by_id": by_id, "name": name}
    expected = apply_and_snapshot(case)
    return {
        "name": name,
        "blocks": encode_blocks(blocks),
        "order": [b.hex() for b in order],
        "expected": expected,
    }


# --- Assemble the vector set --------------------------------------

def main() -> None:
    # The calendar block: the table, boundary rewards, the treasury.
    boundary_slots = [
        0,
        1,
        2,
        24_409_600,  # the end of the first remainder run
        24_409_601,
        BLOCKS_PER_ECLIPSE - 1,
        BLOCKS_PER_ECLIPSE,  # the last slot of eclipse 0
        BLOCKS_PER_ECLIPSE + 1,  # the first slot of eclipse 1
        2 * BLOCKS_PER_ECLIPSE + 1,
        TREASURY_ECLIPSES * BLOCKS_PER_ECLIPSE,  # the last treasury slot
        TREASURY_ECLIPSES * BLOCKS_PER_ECLIPSE + 1,  # the first post-treasury slot
        (ECLIPSES - 1) * BLOCKS_PER_ECLIPSE + 1,  # the last eclipse opens
        ECLIPSES * BLOCKS_PER_ECLIPSE,  # the final slot of the calendar
    ]
    rewards = [
        {
            "slot": slot,
            "reward": reward_of_slot(slot),
            "treasury_share": treasury_share_of(reward_of_slot(slot)),
            "treasury_active": treasury_active_at_slot(slot),
        }
        for slot in boundary_slots
    ]
    # Self-checks: the calendar closes, the eclipse 0 spread closes
    # on its emission, and the first reward is the archived one.
    assert sum(ECLIPSE_EMISSIONS) * 100_000_000 == CAP_ATOMIC
    assert reward_of_slot(1) == 9_792_158
    assert treasury_share_of(9_792_158) == 605_155

    # Case 1: the plain chain.
    chain_blocks = resolve_chain_1()
    case_chain = apply_case("chain-1", chain_blocks)

    # Case 2: the maturity boundary, exactly: the miner output of
    # block 2 (slot 2) spends at slot 12 (mature), then the output
    # of block 3 spends at slot 12 in another chain (immature by
    # one) is a rejection case below. This case only proves the
    # exact boundary is accepted.
    blocks_maturity = [{"height": 0, "txs": []}]
    for height in range(1, 12):
        blocks_maturity.append(
            {
                "height": height,
                "txs": sort_payload([build_coinbase(height, height, 0, MINER_A)]),
            }
        )
    tx_id_2, amount_2 = None, None
    for block in blocks_maturity[1:]:
        coinbase = block["txs"][0]
        if block["height"] == 2:
            tx_id_2, amount_2 = coinbase.tx_id(), coinbase.outputs[0]["amount"]
    fee = 1
    transfer = make_transfer(
        [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
        [output(ALICE, amount_2 - fee)],
        fee,
    )
    coinbase = build_coinbase(12, 12, fee, MINER_A)
    blocks_maturity.append({"height": 12, "txs": sort_payload([coinbase, transfer])})
    case_maturity = apply_case("maturity-exact", blocks_maturity)

    # The rejection battery.
    rejects = []

    rejects.append(
        reject_case(
            "coinbase-value", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="value")]
            ),
        )
    )
    rejects.append(
        reject_case(
            "coinbase-treasury-share", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="treasury_share")]
            ),
        )
    )
    rejects.append(
        reject_case(
            "coinbase-treasury-address", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="treasury_address")]
            ),
        )
    )
    rejects.append(
        reject_case(
            "coinbase-height", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="height")]
            ),
        )
    )
    rejects.append(
        reject_case(
            "coinbase-extra", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="extra")]
            ),
        )
    )
    rejects.append(
        reject_case(
            "coinbase-fee", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="fee")]
            ),
        )
    )
    rejects.append(
        reject_case(
            "coinbase-inputs", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="inputs")]
            ),
        )
    )
    rejects.append(
        reject_case(
            "coinbase-outputs", 3,
            lambda prefix, h: sort_payload(
                [build_coinbase(h, h, 0, MINER_A, mutate="outputs")]
            ),
        )
    )

    def two_coinbases(prefix, h):
        c1 = build_coinbase(h, h, 0, MINER_A)
        c2 = build_coinbase(h, h, 0, MINER_B)
        return sort_payload([c1, c2])

    rejects.append(reject_case("coinbase-count", 3, two_coinbases))

    def double_spend_cross(prefix, h):
        # The first spender at slot 12 (mature), the second at
        # slot 13 (the rejection block).
        tx_id_2, amount_2 = miner_output_of(prefix, 2)
        first = make_transfer(
            [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
            [output(ALICE, amount_2 - 1)],
            1,
        )
        second = make_transfer(
            [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
            [output(BOB, amount_2 - 1)],
            1,
        )
        block12 = {
            "height": 12,
            "txs": sort_payload([build_coinbase(12, 12, 1, MINER_A), first]),
        }
        prefix["blocks"].append(block12)
        prefix["order"].append(block_id_of("double-spend-cross", 13))
        prefix["by_id"][block_id_of("double-spend-cross", 13)] = block12
        return sort_payload([build_coinbase(13, 13, 1, MINER_A), second])

    rejects.append(reject_case("double-spend-cross", 12, double_spend_cross))

    def double_spend_intra(prefix, h):
        tx_id_2, amount_2 = miner_output_of(prefix, 2)
        t1 = make_transfer(
            [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
            [output(ALICE, amount_2 - 1)],
            1,
        )
        t2 = make_transfer(
            [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
            [output(BOB, amount_2 - 1)],
            1,
        )
        return sort_payload([build_coinbase(h, h, 2, MINER_A), t1, t2])

    rejects.append(reject_case("double-spend-intra", 12, double_spend_intra))

    def immature(prefix, h):
        # The miner output of block 3 (slot 3) spent at slot 13 is
        # mature; spent at slot 12 it is one slot early. The
        # rejection block sits at slot 12.
        tx_id_3, amount_3 = miner_output_of(prefix, 3)
        early = make_transfer(
            [unsigned_input(tx_id_3, 0, spend_key_of(MINER_A))],
            [output(ALICE, amount_3 - 1)],
            1,
        )
        return sort_payload([build_coinbase(h, h, 1, MINER_A), early])

    rejects.append(reject_case("immature-by-one", 11, immature))

    def unknown_output(prefix, h):
        nowhere = make_transfer(
            [unsigned_input(keccak256(b"never-created"), 0, random_key())],
            [output(ALICE, 5)],
            1,
        )
        return sort_payload([build_coinbase(h, h, 1, MINER_A), nowhere])

    rejects.append(reject_case("unknown-output", 3, unknown_output))

    def conservation(prefix, h):
        tx_id_2, amount_2 = miner_output_of(prefix, 2)
        short = make_transfer(
            [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
            [output(ALICE, amount_2 - 2)],
            1,
        )
        return sort_payload([build_coinbase(h, h, 1, MINER_A), short])

    rejects.append(reject_case("conservation", 12, conservation))

    def no_inputs(prefix, h):
        empty = make_transfer([], [output(ALICE, 1)], 0)
        return sort_payload([build_coinbase(h, h, 0, MINER_A), empty])

    rejects.append(reject_case("no-inputs", 3, no_inputs))

    def unsorted_payload(prefix, h):
        c = build_coinbase(h, h, 0, MINER_A)
        t = make_transfer(
            [unsigned_input(keccak256(b"never"), 0, random_key())],
            [output(ALICE, 1)],
            1,
        )
        # Deliberately descending: the payload order is broken
        # before any rule about content matters.
        return [t, c] if t.tx_id() > c.tx_id() else [c, t]

    rejects.append(reject_case("unsorted-payload", 3, unsorted_payload))

    # The key binding of ADR-026: two thefts, both correctly
    # signed by the thief, both refused by the ledger alone.

    def theft_of_coinbase(prefix, h):
        # The matured miner output of block 2 (slot 2, mature from
        # slot 12), claimed by the thief's key and paid to the
        # thief's own address. The signature verifies; the key is
        # not the spend key of the output's address.
        tx_id_2, amount_2 = miner_output_of(prefix, 2)
        thief_seed = random_seed_bytes()
        fee = 1
        theft = signed_thief_transfer(
            tx_id_2, 0, thief_seed, thief_destination(thief_seed), amount_2 - fee, fee
        )
        return sort_payload([build_coinbase(h, h, fee, MINER_A), theft])

    rejects.append(
        reject_case("key-not-bound-coinbase", 12, theft_of_coinbase, expect="KeyNotBound")
    )

    def theft_of_transfer():
        """A correctly-signed theft of a transfer output: the setup
        block pays Alice honestly, the theft block claims her
        output with the thief's key. The prefix runs to slot 12 so
        the miner output of block 2 is mature for the setup spend;
        Alice's output is a transfer output, no maturity applies —
        only the binding can refuse the thief."""
        name = "key-not-bound-transfer"
        prefix = coinbase_only_prefix(name, 12, MINER_A)
        tx_id_2, amount_2 = miner_output_of(prefix, 2)
        fee = 1
        setup = make_transfer(
            [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
            [output(ALICE, amount_2 - fee)],
            fee,
        )
        setup_block = {
            "height": 13,
            "txs": sort_payload([build_coinbase(13, 13, fee, MINER_A), setup]),
        }
        alice_tx, alice_amount = setup.tx_id(), setup.outputs[0]["amount"]
        thief_seed = random_seed_bytes()
        fee2 = 1
        theft = signed_thief_transfer(
            alice_tx, 0, thief_seed, thief_destination(thief_seed), alice_amount - fee2, fee2
        )
        theft_block = {
            "height": 14,
            "txs": sort_payload([build_coinbase(14, 14, fee2, MINER_A), theft]),
        }
        blocks = prefix["blocks"] + [setup_block, theft_block]
        order = [block_id_of(name, i) for i in range(len(blocks))]
        by_id = {block_id_of(name, i): blocks[i] for i in range(len(blocks))}

        # The Python ledger must name the binding and stand at the
        # setup state, prefix plus the honest spend.
        ledger = Ledger()
        error = None
        try:
            ledger.apply_order(order, fetch_of(by_id))
        except StateError as e:
            error = e.name
        assert error == "KeyNotBound", f"reject case {name} fired {error}"
        good = Ledger()
        good.apply_order(
            prefix["order"] + [block_id_of(name, 13)], fetch_of(by_id)
        )
        assert ledger.snapshot() == good.snapshot(), (
            f"reject case {name} mutated the ledger"
        )
        return {
            "name": name,
            "blocks": encode_blocks(blocks),
            "order": [b.hex() for b in order],
            "error": error,
            "after_reject": {"stats": ledger.stats(), "utxos": ledger.snapshot()},
        }

    rejects.append(theft_of_transfer())

    # The reorg: a shared prefix, two suffixes, two rebuilds.
    prefix = coinbase_only_prefix("reorg", 11, MINER_A)
    pool = dict(prefix["by_id"])
    order_a = list(prefix["order"])
    order_b = list(prefix["order"])

    # Suffix A: two coinbase-only blocks.
    for offset, height in enumerate((12, 13), start=12):
        block = {
            "height": height,
            "txs": sort_payload([build_coinbase(height, height, 0, MINER_A)]),
        }
        block_id = block_id_of("reorg-a", offset)
        pool[block_id] = block
        order_a.append(block_id)

    # Suffix B: three blocks; the last spends the matured miner
    # output of prefix block 2 (slot 2, mature from slot 12).
    for offset, height in enumerate((12, 13, 14), start=12):
        if height == 14:
            tx_id_2, amount_2 = miner_output_of(prefix, 2)
            fee = 1
            transfer = make_transfer(
                [unsigned_input(tx_id_2, 0, spend_key_of(MINER_A))],
                [output(CAROL, amount_2 - fee)],
                fee,
            )
            block = {
                "height": height,
                "txs": sort_payload(
                    [build_coinbase(height, height, fee, MINER_B), transfer]
                ),
            }
        else:
            block = {
                "height": height,
                "txs": sort_payload([build_coinbase(height, height, 0, MINER_B)]),
            }
        block_id = block_id_of("reorg-b", offset)
        pool[block_id] = block
        order_b.append(block_id)

    expected_a = apply_and_snapshot({"order": order_a, "by_id": pool, "name": "reorg-a"})
    expected_b = apply_and_snapshot({"order": order_b, "by_id": pool, "name": "reorg-b"})
    assert expected_a["utxos"] != expected_b["utxos"], "the reorg is a no-op"
    reorg = {
        "pool": {
            block_id.hex(): {
                "height": block["height"],
                "txs": [t.encode().hex() for t in block["txs"]],
            }
            for block_id, block in sorted(pool.items())
        },
        "order_a": [b.hex() for b in order_a],
        "order_b": [b.hex() for b in order_b],
        "expected_a": expected_a,
        "expected_b": expected_b,
    }

    # Encode-decode-encode identity over every generated
    # transaction, the signed thefts included.
    for case in [case_chain, case_maturity] + rejects:
        for block in case["blocks"]:
            for tx_hex in block["txs"]:
                tx = Tx.decode(bytes.fromhex(tx_hex))
                assert tx.encode().hex() == tx_hex, "the codec is not the identity"

    vectors = {
        "format": 1,
        "comment": (
            "ANTUMBRA state layer cross vectors: the emission "
            "calendar, the coinbase rules, the UTXO ledger over "
            "generated orders (the key binding of ADR-026: honest "
            "inputs claim the spend key of the output's address, "
            "correctly-signed thefts are refused), the rejection "
            "battery and the reorg rebuild. Produced by "
            "gen_state_vectors.py; the Rust suite must agree bit "
            "for bit."
        ),
        "generator": {"seed": SEED, "implementation": "python3 + pycryptodome"},
        "calendar": {
            "cap_atomic": CAP_ATOMIC,
            "blocks_per_eclipse": BLOCKS_PER_ECLIPSE,
            "maturity": MATURITY,
            "eclipses_atu": ECLIPSE_EMISSIONS,
            "rewards": rewards,
            "treasury_address": TREASURY_ADDRESS.hex(),
        },
        "apply": [case_chain, case_maturity],
        "reject": rejects,
        "reorg": reorg,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vectors, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
    print(f"calendar: {len(ECLIPSE_EMISSIONS)} eclipses, cap closes: "
          f"{sum(ECLIPSE_EMISSIONS) * 100_000_000 == CAP_ATOMIC}")
    print(f"apply cases: {len(vectors['apply'])}")
    print(f"reject cases: {len(vectors['reject'])}")
    print(f"reorg: order A {len(order_a)} blocks, order B {len(order_b)} blocks")


if __name__ == "__main__":
    main()
