#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-dag.

Independent re-implementation of every output-producing routine
of the ordering layer (ADR-013): the canonical header and block
encodings, the block id, the payload root, the work function
(leading zero bits, the mining walk), the insertion rule
battery, the GHOSTDAG-family coloring (blue sets, blue scores,
selected parents) and the consensus order. Keccak-256 comes from
pycryptodome; the varint, the header codec, the block codec, the
DAG store, the coloring and the order are re-implemented from the
ADR text alone. The output is the archived vector set consumed by
the Rust test suite: both implementations must agree bit for bit
(CONTRIBUTING.md, verification layer 1).

The generator also decodes: a Python reader mirrors the strict
decoding rules (canonical varints, structural limits, strictly
ascending parents and transaction ids, payload root commitment, no
trailing bytes) and every generated header and block must survive
encode-decode-encode unchanged. Every DAG construction replays
the full insertion battery, then the self-checks assert the
invariants the ADR states: the blue set lives in the past, the
selected parent is blue, the inherited blues survive, the score is
one plus the blue set, the order is a topological permutation of
the view and never reshuffles along the selected-parent chain. A
vector set that does not pass its own self-checks is never
written.

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339, the golden ratio scaled, the number that
already drives the emission calendar). No Python random module, no
version drift, byte-for-byte reproducible on any machine.

Usage: python3 code/scripts/gen_dag_vectors.py
Writes: code/crates/antumbra-dag/tests/vectors.json
"""

import json
import sys
from pathlib import Path

from Crypto.Hash import keccak

OUTPUT = Path(__file__).resolve().parents[1] / "crates" / "antumbra-dag" / "tests" / "vectors.json"

# --- Constants mirrored from ADR-013 and the Rust crate ----------

VERSION_1 = 1
MAX_PARENTS = 16
MAX_TXS = 64
K = 8
GENESIS_TIMESTAMP_MS = 1_750_000_000_000
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
        """`count` pairwise distinct 32-byte strings."""
        out: set[bytes] = set()
        while len(out) < count:
            out.add(self.bytes(32))
        return sorted(out)


# --- Varint (canonical unsigned LEB128) --------------------------

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
    """The Python twin of DagError: a name and nothing else."""

    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


# --- The codecs ----------------------------------------------------

def header_encode(parents: list[bytes], height: int, timestamp: int,
                  nonce: int, payload_root: bytes) -> bytes:
    out = bytearray()
    out += VERSION_1.to_bytes(2, "little")
    out += write_varint(len(parents))
    for parent in parents:
        out += parent
    out += height.to_bytes(8, "little")
    out += timestamp.to_bytes(8, "little")
    out += nonce.to_bytes(8, "little")
    out += payload_root
    return bytes(out)


def payload_root(tx_ids: list[bytes]) -> bytes:
    return keccak256(write_varint(len(tx_ids)) + b"".join(tx_ids))


def block_encode(parents: list[bytes], height: int, timestamp: int,
                 nonce: int, tx_ids: list[bytes]) -> bytes:
    root = payload_root(tx_ids)
    return header_encode(parents, height, timestamp, nonce, root) \
        + write_varint(len(tx_ids)) + b"".join(tx_ids)


def decode_header(data: bytes) -> tuple[list[bytes], int, int, int, bytes]:
    """Strict header decode; returns the five header fields."""
    pos = 0
    if len(data) < 2:
        raise Reject("Decode")
    version = int.from_bytes(data[pos:pos + 2], "little")
    pos += 2
    if version != VERSION_1:
        raise Reject("InvalidVersion")
    count, consumed = read_varint(data, pos)
    pos += consumed
    if count == 0:
        raise Reject("NoParents")
    if count > MAX_PARENTS:
        raise Reject("TooManyParents")
    parents = []
    for _ in range(count):
        if pos + 32 > len(data):
            raise Reject("Decode")
        parents.append(data[pos:pos + 32])
        pos += 32
    for a, b in zip(parents, parents[1:]):
        if a >= b:
            raise Reject("UnsortedParents")
    if pos + 24 > len(data):
        raise Reject("Decode")
    height = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    timestamp = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    nonce = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    if pos + 32 > len(data):
        raise Reject("Decode")
    root = data[pos:pos + 32]
    pos += 32
    if pos != len(data):
        raise Reject("Decode")
    return parents, height, timestamp, nonce, root


def decode_block(data: bytes) -> tuple[list[bytes], int, int, int, list[bytes]]:
    """Strict block decode; the root must commit the payload."""
    pos = 0
    if len(data) < 2:
        raise Reject("Decode")
    version = int.from_bytes(data[pos:pos + 2], "little")
    pos += 2
    if version != VERSION_1:
        raise Reject("InvalidVersion")
    count, consumed = read_varint(data, pos)
    pos += consumed
    if count == 0:
        raise Reject("NoParents")
    if count > MAX_PARENTS:
        raise Reject("TooManyParents")
    parents = []
    for _ in range(count):
        if pos + 32 > len(data):
            raise Reject("Decode")
        parents.append(data[pos:pos + 32])
        pos += 32
    for a, b in zip(parents, parents[1:]):
        if a >= b:
            raise Reject("UnsortedParents")
    if pos + 24 > len(data):
        raise Reject("Decode")
    height = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    timestamp = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    nonce = int.from_bytes(data[pos:pos + 8], "little")
    pos += 8
    if pos + 32 > len(data):
        raise Reject("Decode")
    root = data[pos:pos + 32]
    pos += 32
    tx_count, consumed = read_varint(data, pos)
    pos += consumed
    if tx_count > MAX_TXS:
        raise Reject("TooManyTransactions")
    tx_ids = []
    for _ in range(tx_count):
        if pos + 32 > len(data):
            raise Reject("Decode")
        tx_ids.append(data[pos:pos + 32])
        pos += 32
    for a, b in zip(tx_ids, tx_ids[1:]):
        if a >= b:
            raise Reject("UnsortedTransactions")
    if pos != len(data):
        raise Reject("Decode")
    if payload_root(tx_ids) != root:
        raise Reject("PayloadRootMismatch")
    return parents, height, timestamp, nonce, tx_ids


# --- The work function ---------------------------------------------

def leading_zero_bits(digest: bytes) -> int:
    total = 0
    for byte in digest:
        if byte != 0:
            return total + 8 - byte.bit_length()
        total += 8
    return total


def meets(digest: bytes, bits: int) -> bool:
    return leading_zero_bits(digest) >= bits


def mine(parents: list[bytes], height: int, timestamp: int,
         root: bytes, bits: int, max_attempts: int) -> int:
    """The deterministic walk: nonce from zero until the id meets
    the difficulty. Both implementations must find the same
    nonce."""
    for nonce in range(max_attempts):
        digest = keccak256(header_encode(parents, height, timestamp, nonce, root))
        if meets(digest, bits):
            return nonce
    raise RuntimeError("the mining walk found nothing; raise the attempts")


# --- The DAG -------------------------------------------------------

class Dag:
    """The Python twin of the Rust store: same rules, same order."""

    def __init__(self, genesis_timestamp: int, genesis_tx_ids: list[bytes]):
        root = payload_root(genesis_tx_ids)
        gid = keccak256(header_encode([ZERO], 0, genesis_timestamp, 0, root))
        self.genesis = gid
        self.nodes = {
            gid: {
                "parents": [],
                "height": 0,
                "timestamp": genesis_timestamp,
                "nonce": 0,
                "tx_ids": list(genesis_tx_ids),
                "past": set(),
                "blues": set(),
                "score": 1,
                "sp": None,
                "children": set(),
            }
        }
        self.tips = {gid}

    def insert(self, parents: list[bytes], height: int, timestamp: int,
               nonce: int, tx_ids: list[bytes],
               difficulty_bits: int, max_future: int, now: int) -> bytes:
        # The rule battery, in the exact order of the ADR.
        root = payload_root(tx_ids)
        block_id = keccak256(header_encode(parents, height, timestamp, nonce, root))
        if block_id in self.nodes:
            raise Reject("Duplicate")
        if len(parents) == 1 and parents[0] == ZERO:
            raise Reject("ZeroParent")
        for parent in parents:
            if parent not in self.nodes:
                raise Reject("UnknownParent")
        past: set[bytes] = set()
        computed_height = 0
        max_parent_ts = 0
        for parent in parents:
            node = self.nodes[parent]
            past |= node["past"]
            past.add(parent)
            computed_height = max(computed_height, node["height"] + 1)
            max_parent_ts = max(max_parent_ts, node["timestamp"])
        if height != computed_height:
            raise Reject("HeightMismatch")
        if timestamp < max_parent_ts:
            raise Reject("TimestampBehind")
        limit = min(now + max_future, U64_MAX)
        if timestamp > limit:
            raise Reject("TimestampFuture")
        if leading_zero_bits(block_id) < difficulty_bits:
            raise Reject("InsufficientWork")

        # The selected parent: highest score, ties by smallest id.
        sp = min(parents, key=lambda p: (-self.nodes[p]["score"], p))
        sp_node = self.nodes[sp]

        # The coloring of ADR-013.
        working = set(sp_node["blues"])
        working.add(sp)
        candidates = [h for h in past if h != sp and h not in sp_node["past"]]
        candidates.sort(key=lambda h: (-self.nodes[h]["score"], h))
        for candidate in candidates:
            candidate_past = self.nodes[candidate]["past"]
            count = 0
            for u in working:
                if u == candidate:
                    continue
                if u in candidate_past:
                    continue
                if candidate in self.nodes[u]["past"]:
                    continue
                count += 1
            if count <= K:
                working.add(candidate)
        score = len(working) + 1

        self.nodes[block_id] = {
            "parents": list(parents),
            "height": height,
            "timestamp": timestamp,
            "nonce": nonce,
            "tx_ids": list(tx_ids),
            "past": past,
            "blues": working,
            "score": score,
            "sp": sp,
            "children": set(),
        }
        for parent in parents:
            self.nodes[parent]["children"].add(block_id)
            self.tips.discard(parent)
        self.tips.add(block_id)
        return block_id

    def best_tip(self) -> bytes:
        return min(self.tips, key=lambda t: (-self.nodes[t]["score"], t))

    def consensus_order(self, tip: bytes) -> list[bytes]:
        chain = [tip]
        while self.nodes[chain[-1]]["sp"] is not None:
            chain.append(self.nodes[chain[-1]]["sp"])
        chain.reverse()
        order = [self.genesis]
        previous_view = {self.genesis}
        for block_id in chain[1:]:
            view = set(self.nodes[block_id]["past"])
            view.add(block_id)
            fresh = [h for h in view if h not in previous_view]
            fresh.sort(key=lambda h: (self.nodes[h]["height"], h))
            order.extend(fresh)
            previous_view = view
        return order


# --- Self-checks ---------------------------------------------------

def check_dag_invariants(dag: Dag, ids: list[bytes]) -> None:
    """The invariants the ADR states must hold on every set."""
    assert len(dag.nodes) == len(ids)
    assert ids[0] == dag.genesis
    for bid in ids:
        node = dag.nodes[bid]
        # The past is exactly the transitive ancestors.
        recomputed: set[bytes] = set()
        for parent in node["parents"]:
            recomputed |= dag.nodes[parent]["past"]
            recomputed.add(parent)
        assert node["past"] == recomputed, "the past is the transitive ancestors"
        # The score is one plus the blue set, which lives in the past.
        assert node["score"] == len(node["blues"]) + 1
        for blue in node["blues"]:
            assert blue in node["past"], "a blue block is an ancestor"
        if node["sp"] is None:
            assert bid == dag.genesis
            assert node["parents"] == []
        else:
            assert node["sp"] in node["parents"]
            assert node["sp"] in node["blues"], "the selected parent is blue"
            sp_node = dag.nodes[node["sp"]]
            assert sp_node["blues"] | {node["sp"]} <= node["blues"], "blues survive"
            assert node["score"] > sp_node["score"]
        # The height and the timestamp rules.
        for parent in node["parents"]:
            assert node["height"] > dag.nodes[parent]["height"]
            assert node["timestamp"] >= dag.nodes[parent]["timestamp"]
    # The tips are the childless blocks.
    for bid in ids:
        childless = not dag.nodes[bid]["children"]
        assert (bid in dag.tips) == childless
    # The order of the best tip: a topological permutation of its
    # view, ending on the tip, never reshuffling along the chain.
    tip = dag.best_tip()
    order = dag.consensus_order(tip)
    view = set(dag.nodes[tip]["past"])
    view.add(tip)
    assert sorted(order) == sorted(view), "the order is a permutation of the view"
    assert order[0] == dag.genesis
    assert order[-1] == tip, "the tip is last: its height is maximal"
    position = {bid: i for i, bid in enumerate(order)}
    for bid in order:
        for parent in dag.nodes[bid]["parents"]:
            assert position[parent] < position[bid], "the order is topological"
    chain = [tip]
    while dag.nodes[chain[-1]]["sp"] is not None:
        chain.append(dag.nodes[chain[-1]]["sp"])
    for chain_block in chain:
        prefix = dag.consensus_order(chain_block)
        assert order[:len(prefix)] == prefix, "the order never reshuffles"


# --- Vector construction -------------------------------------------

# The textbook structure: a fork on the genesis, a merge, a second
# fork, its merge, and a merge with the older branch.
TEXTBOOK = [[0], [0], [1, 2], [3], [4], [4], [5, 6], [7, 2], [8]]


def build_from_structure(seed: int, structure: list[list[int]]) -> tuple[Dag, list[bytes]]:
    lcg = Lcg(seed)
    dag = Dag(GENESIS_TIMESTAMP_MS, [])
    ids = [dag.genesis]
    for parents_idx in structure:
        tx_count = lcg.next_below(3)
        tx_ids = sorted({lcg.bytes(32) for _ in range(tx_count)})
        height = 1 + max(dag.nodes[ids[j]]["height"] for j in parents_idx)
        ts = 1 + max(dag.nodes[ids[j]]["timestamp"] for j in parents_idx) \
            + lcg.next_below(2_000)
        nonce = lcg.next_u64()
        parent_ids = sorted(ids[j] for j in parents_idx)
        dag.insert(parent_ids, height, ts, nonce, tx_ids, 0, U64_MAX, U64_MAX)
        ids.append(keccak256(header_encode(
            parent_ids, height, ts, nonce, payload_root(tx_ids))))
    return dag, ids


def build_wide_fork(seed: int) -> tuple[Dag, list[bytes]]:
    """Twelve blocks racing on the genesis, then the merge: the
    anticone bound K must turn the last candidates red."""
    lcg = Lcg(seed)
    dag = Dag(GENESIS_TIMESTAMP_MS, [])
    ids = [dag.genesis]
    for _ in range(12):
        ts = GENESIS_TIMESTAMP_MS + 2_000 + lcg.next_below(2_000)
        nonce = lcg.next_u64()
        dag.insert([dag.genesis], 1, ts, nonce, [], 0, U64_MAX, U64_MAX)
        ids.append(keccak256(header_encode(
            [dag.genesis], 1, ts, nonce, payload_root([]))))
    merge_parents = sorted(ids[1:13])
    ts = GENESIS_TIMESTAMP_MS + 4_000
    nonce = lcg.next_u64()
    dag.insert(merge_parents, 2, ts, nonce, [], 0, U64_MAX, U64_MAX)
    ids.append(keccak256(header_encode(
        merge_parents, 2, ts, nonce, payload_root([]))))
    for _ in range(2):
        parent = ids[-1]
        height = dag.nodes[parent]["height"] + 1
        ts = dag.nodes[parent]["timestamp"] + 2_000
        nonce = lcg.next_u64()
        dag.insert([parent], height, ts, nonce, [], 0, U64_MAX, U64_MAX)
        ids.append(keccak256(header_encode(
            [parent], height, ts, nonce, payload_root([]))))
    return dag, ids


def build_random(seed: int, count: int, tip_bias: int) -> tuple[Dag, list[bytes]]:
    """A deterministic random DAG: parents mostly among the tips,
    sometimes older, so forks and wide anticones both occur."""
    lcg = Lcg(seed)
    dag = Dag(GENESIS_TIMESTAMP_MS, [])
    ids = [dag.genesis]
    while len(ids) < count:
        existing = len(ids)
        want = 1 + lcg.next_below(min(3, existing))
        parent_set: set[int] = set()
        tip_index = [i for i, bid in enumerate(ids) if bid in dag.tips]
        for _ in range(want):
            if lcg.next_below(4) < tip_bias and tip_index:
                parent_set.add(tip_index[lcg.next_below(len(tip_index))])
            else:
                parent_set.add(lcg.next_below(existing))
        if not parent_set:
            parent_set.add(existing - 1)
        parents_idx = sorted(parent_set, key=lambda j: ids[j])
        tx_count = lcg.next_below(4)
        tx_ids = sorted({lcg.bytes(32) for _ in range(tx_count)})
        height = 1 + max(dag.nodes[ids[j]]["height"] for j in parents_idx)
        ts = 1 + max(dag.nodes[ids[j]]["timestamp"] for j in parents_idx) \
            + lcg.next_below(2_000)
        nonce = lcg.next_u64()
        parent_ids = sorted(ids[j] for j in parents_idx)
        dag.insert(parent_ids, height, ts, nonce, tx_ids, 0, U64_MAX, U64_MAX)
        ids.append(keccak256(header_encode(
            parent_ids, height, ts, nonce, payload_root(tx_ids))))
    return dag, ids


def dag_to_vector(dag: Dag, ids: list[bytes]) -> dict:
    index = {bid: i for i, bid in enumerate(ids)}
    tip = dag.best_tip()
    order = dag.consensus_order(tip)
    return {
        "nodes": [
            {
                "parents": [index[p] for p in dag.nodes[bid]["parents"]],
                "height": dag.nodes[bid]["height"],
                "timestamp": dag.nodes[bid]["timestamp"],
                "nonce": dag.nodes[bid]["nonce"],
                "tx_ids": [t.hex() for t in dag.nodes[bid]["tx_ids"]],
                "id": bid.hex(),
                "blue_score": dag.nodes[bid]["score"],
                "selected_parent": None if dag.nodes[bid]["sp"] is None
                else index[dag.nodes[bid]["sp"]],
                "blue_set": sorted(index[b] for b in dag.nodes[bid]["blues"]),
            }
            for bid in ids
        ],
        "tip": index[tip],
        "order": [index[b] for b in order],
    }


def main() -> int:
    lcg = Lcg(16_180_339)

    # --- The genesis block ------------------------------------
    genesis_root = payload_root([])
    genesis_header = header_encode([ZERO], 0, GENESIS_TIMESTAMP_MS, 0, genesis_root)
    genesis_canonical = genesis_header + write_varint(0)
    genesis_id = keccak256(genesis_header)
    assert decode_block(genesis_canonical) == ([ZERO], 0, GENESIS_TIMESTAMP_MS, 0, [])
    genesis_vector = {
        "timestamp": GENESIS_TIMESTAMP_MS,
        "payload_root": genesis_root.hex(),
        "canonical_hex": genesis_canonical.hex(),
        "id": genesis_id.hex(),
    }

    # --- Header vectors ----------------------------------------
    header_vectors = []
    header_shapes = [1, 2, 16, 1, 2, 3, 1, 4, 1, 2, 3, 1]
    for count in header_shapes:
        parents = lcg.distinct(count)
        height = 1 + lcg.next_below(1_000)
        timestamp = lcg.next_u64() >> 8
        nonce = lcg.next_u64()
        root = lcg.bytes(32)
        canonical = header_encode(parents, height, timestamp, nonce, root)
        assert decode_header(canonical) == (parents, height, timestamp, nonce, root)
        header_vectors.append({
            "parents": [p.hex() for p in parents],
            "height": height,
            "timestamp": timestamp,
            "nonce": nonce,
            "payload_root": root.hex(),
            "canonical_hex": canonical.hex(),
            "id": keccak256(canonical).hex(),
        })
    # The sixteen-parent boundary is really covered.
    assert any(len(v["parents"]) == 16 for v in header_vectors)

    # --- Block vectors -----------------------------------------
    block_vectors = []
    block_shapes = [0, 1, 3, 8, 64, 3]
    for tx_count in block_shapes:
        parents = lcg.distinct(2)
        tx_ids = lcg.distinct(tx_count)
        height = 1 + lcg.next_below(1_000)
        timestamp = lcg.next_u64() >> 8
        nonce = lcg.next_u64()
        root = payload_root(tx_ids)
        header = header_encode(parents, height, timestamp, nonce, root)
        canonical = header + write_varint(len(tx_ids)) + b"".join(tx_ids)
        assert decode_block(canonical) == (parents, height, timestamp, nonce, tx_ids)
        block_vectors.append({
            "parents": [p.hex() for p in parents],
            "height": height,
            "timestamp": timestamp,
            "nonce": nonce,
            "tx_ids": [t.hex() for t in tx_ids],
            "canonical_hex": canonical.hex(),
            "id": keccak256(header).hex(),
        })
    assert any(len(v["tx_ids"]) == 64 for v in block_vectors)

    # --- Work vectors -------------------------------------------
    pow_vectors = []
    for bits in (8, 8, 8, 12, 12, 12):
        parents = lcg.distinct(2)
        height = 1 + lcg.next_below(1_000)
        timestamp = lcg.next_u64() >> 8
        root = lcg.bytes(32)
        nonce = mine(parents, height, timestamp, root, bits, 1 << 24)
        digest = keccak256(header_encode(parents, height, timestamp, nonce, root))
        found = leading_zero_bits(digest)
        assert found >= bits
        assert nonce == mine(parents, height, timestamp, root, bits, 1 << 24)
        pow_vectors.append({
            "parents": [p.hex() for p in parents],
            "height": height,
            "timestamp": timestamp,
            "payload_root": root.hex(),
            "bits": bits,
            "nonce": nonce,
            "id": digest.hex(),
            "leading_bits": found,
        })

    # --- DAG vectors ---------------------------------------------
    dag_vectors = []

    handcrafted, hand_ids = build_from_structure(0xA0D0A0D0, TEXTBOOK)
    check_dag_invariants(handcrafted, hand_ids)
    dag_vectors.append(dag_to_vector(handcrafted, hand_ids))

    wide, wide_ids = build_wide_fork(0xFEEDFEED)
    check_dag_invariants(wide, wide_ids)
    reds = sum(
        len(wide.nodes[bid]["past"]) - len(wide.nodes[bid]["blues"])
        for bid in wide_ids if wide.nodes[bid]["sp"] is not None
    )
    assert reds > 0, "the wide fork must produce red blocks"
    dag_vectors.append(dag_to_vector(wide, wide_ids))

    random_a, ids_a = build_random(0x1A0DA6A, 24, 3)
    check_dag_invariants(random_a, ids_a)
    dag_vectors.append(dag_to_vector(random_a, ids_a))

    random_b, ids_b = build_random(0x0DA6A0B, 48, 2)
    check_dag_invariants(random_b, ids_b)
    dag_vectors.append(dag_to_vector(random_b, ids_b))

    # --- Invalid decode vectors ----------------------------------
    base_parents = lcg.distinct(2)
    base_tx = lcg.distinct(2)
    base = block_encode(base_parents, 5, GENESIS_TIMESTAMP_MS, 99, base_tx)
    header_len = 2 + 1 + 32 * len(base_parents) + 24 + 32

    # A descending parent list, manufactured directly.
    p1, p2 = lcg.distinct(2)
    unsorted = header_encode([p2, p1], 5, 1, 1, lcg.bytes(32))

    invalid_vectors = [
        {"hex": (b"\x02\x00" + base[2:]).hex(), "error": "InvalidVersion"},
        {"hex": header_encode(lcg.distinct(17), 5, 1, 1,
                              lcg.bytes(32)).hex(), "error": "TooManyParents"},
        {"hex": unsorted.hex(), "error": "UnsortedParents"},
        {"hex": (VERSION_1.to_bytes(2, "little") + b"\x00").hex(),
         "error": "NoParents"},
        {"hex": (base + b"\x00").hex(), "error": "Decode"},
        {"hex": block_encode(base_parents, 5, GENESIS_TIMESTAMP_MS, 99,
                             [base_tx[1], base_tx[0]]).hex(),
         "error": "UnsortedTransactions"},
        {"hex": block_encode(base_parents, 5, GENESIS_TIMESTAMP_MS, 99,
                             lcg.distinct(65)).hex(),
         "error": "TooManyTransactions"},
    ]
    # A root that does not commit the payload.
    wrong_root = bytearray(base)
    wrong_root[header_len - 1] ^= 0xFF
    invalid_vectors.append({"hex": bytes(wrong_root).hex(),
                            "error": "PayloadRootMismatch"})

    for vector in invalid_vectors:
        try:
            decode_block(bytes.fromhex(vector["hex"]))
        except Reject as e:
            assert e.name == vector["error"], \
                f"expected {vector['error']}, got {e.name}"
        else:
            raise AssertionError(f"the bytes must be rejected: {vector['error']}")

    # --- Insertion rejection vectors ------------------------------
    reject_vectors = []

    def reject_case(parents, height, timestamp, nonce, tx_ids,
                    error, bits=0, future=U64_MAX, now=U64_MAX):
        """`parents` is a list of block ids (bytes); the zero hash
        and unknown hashes are legal inputs to the rejection
        battery."""
        dag, ids = build_from_structure(0xA0D0A0D0, TEXTBOOK)
        parent_ids = sorted(parents)
        try:
            dag.insert(parent_ids, height, timestamp, nonce, tx_ids,
                       bits, future, now)
        except Reject as e:
            assert e.name == error, f"expected {error}, got {e.name}"
        else:
            raise AssertionError(f"the insertion must be rejected: {error}")
        reject_vectors.append({
            "parents": [p.hex() for p in parent_ids],
            "height": height,
            "timestamp": timestamp,
            "nonce": nonce,
            "tx_ids": [t.hex() for t in tx_ids],
            "difficulty_bits": bits,
            "max_future_ms": future,
            "now_ms": now,
            "error": error,
        })

    textbook, textbook_ids = build_from_structure(0xA0D0A0D0, TEXTBOOK)
    node_one = textbook.nodes[textbook_ids[1]]
    reject_case([lcg.bytes(32)], 1, GENESIS_TIMESTAMP_MS + 2_000, 0, [],
                "UnknownParent")
    reject_case([ZERO], 1, GENESIS_TIMESTAMP_MS + 2_000, 0, [],
                "ZeroParent")
    reject_case([textbook_ids[1]], 5, GENESIS_TIMESTAMP_MS + 20_000, 0, [],
                "HeightMismatch")
    reject_case([textbook_ids[1]], 2, GENESIS_TIMESTAMP_MS, 0, [],
                "TimestampBehind")
    reject_case([textbook_ids[1]], 2, 1 << 50, 0, [],
                "TimestampFuture", bits=0, future=1_000, now=0)
    reject_case([textbook_ids[1]], 2, GENESIS_TIMESTAMP_MS + 20_000, 0, [],
                "InsufficientWork", bits=200, future=U64_MAX, now=U64_MAX)
    # The duplicate: node one of the textbook DAG, replayed byte
    # for byte.
    reject_case([textbook_ids[0]], node_one["height"], node_one["timestamp"],
                node_one["nonce"], node_one["tx_ids"], "Duplicate")

    # --- Write ------------------------------------------------------
    vectors = {
        "format": 1,
        "generator": "code/scripts/gen_dag_vectors.py (pycryptodome, independent implementation)",
        "genesis": genesis_vector,
        "header": header_vectors,
        "block": block_vectors,
        "pow": pow_vectors,
        "dag": dag_vectors,
        "invalid": invalid_vectors,
        "insert_reject": reject_vectors,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"OK: {len(header_vectors)} header, {len(block_vectors)} block, "
          f"{len(pow_vectors)} work, {len(dag_vectors)} dag, "
          f"{len(invalid_vectors)} invalid, {len(reject_vectors)} rejection "
          f"vectors written to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
