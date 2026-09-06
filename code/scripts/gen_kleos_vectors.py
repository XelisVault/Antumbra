#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-kleos.

Independent re-implementation of every output-producing routine of
the reputation machine (ADR-003, ADR-015): the millipoint state
machine (era transition with decay and saturation, the sanctions:
fraud conviction, liable witness, liable sponsor, seat stripping),
the queries (witness weight, Ring candidacy, the total), the
closed-graph discounts and the Echo helpers (R4, R2, the per-target
cap), and the era draw over its Keccak word stream (weighted,
without replacement, modulo over the live pool). Keccak-256 comes
from pycryptodome; the state machine, the helpers and the draw are
re-implemented from the ADR text alone. The output is the archived
vector set consumed by the Rust test suite: both implementations
must agree bit for bit (CONTRIBUTING.md, verification layer 1).

The state vectors record the state after every operation, so a
divergence is caught at the exact step that causes it, not at the
end of a long sequence. The draw vectors cover the quorum shapes
of an era: a full pool, a short pool, zero-weight whales that must
never be drawn, a pool that exhausts its weight, and the two
rejection paths (a weightless pool, candidates not strictly
ascending).

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339, the golden ratio scaled, the number
that already drives the emission calendar). No Python random
module, no version drift, byte-for-byte reproducible on any
machine.

Usage: python3 code/scripts/gen_kleos_vectors.py
Writes: code/crates/antumbra-kleos/tests/vectors.json
"""

import json
from pathlib import Path

from Crypto.Hash import keccak

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "crates"
    / "antumbra-kleos"
    / "tests"
    / "vectors.json"
)

# --- Constants mirrored from ADR-015 and the Rust crate ----------

DEED_MAX = 40_000
ECHO_MAX = 30_000
TENURE_MAX = 30_000
DEED_DECAY = 100
ECHO_DECAY = 50
ECHO_TARGET_CAP = 2_000
W_MIN = 150
WITNESS_MIN_DEED = 20_000
RING_THRESHOLD = 70_000
RING_MIN_TENURE = 15_000
WITNESS_PENALTY = 3_000
SPONSOR_PENALTY = 5_000
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

    def distinct_sorted(self, count: int) -> list[bytes]:
        out: set[bytes] = set()
        while len(out) < count:
            out.add(self.bytes(32))
        return sorted(out)


# --- The word stream, from the ADR text alone --------------------
#
# word(i) = the first sixteen unread bytes of
# Keccak-256(entropy || u64_le(counter)), little endian: one
# Keccak block carries two words, the next block is hashed on
# demand, the counter increments per block.


def word_stream(entropy: bytes, count: int) -> list[int]:
    words: list[int] = []
    counter = 0
    while len(words) < count:
        block = keccak256(entropy + counter.to_bytes(8, "little"))
        words.append(int.from_bytes(block[0:16], "little"))
        if len(words) < count:
            words.append(int.from_bytes(block[16:32], "little"))
        counter += 1
    return words


# --- The state machine, from the ADR text alone ------------------
#
# A state is [deed, echo, tenure, tenure_dead] in millipoints.


def advance_era(state: list, deed_gain: int, echo_gain: int) -> list:
    deed, echo, tenure, dead = state
    deed = min(max(deed + deed_gain - DEED_DECAY, 0), DEED_MAX)
    echo = min(max(echo + echo_gain - ECHO_DECAY, 0), ECHO_MAX)
    if not dead:
        tenure = min(tenure + 1, TENURE_MAX)
    return [deed, echo, tenure, dead]


def convict_fraud(state: list) -> list:
    deed, _echo, _tenure, _dead = state
    return [deed // 2, 0, 0, True]


def penalize_witness(state: list) -> list:
    deed, echo, tenure, dead = state
    return [max(deed - WITNESS_PENALTY, 0), echo, tenure, dead]


def penalize_sponsor(state: list) -> list:
    deed, echo, tenure, dead = state
    return [max(deed - SPONSOR_PENALTY, 0), echo, tenure, dead]


def strip(state: list) -> list:
    return [0, 0, 0, True]


def witness_weight(state: list) -> int:
    deed = state[0]
    if deed < WITNESS_MIN_DEED:
        return 0
    return W_MIN + 850 * (deed - WITNESS_MIN_DEED) // (DEED_MAX - WITNESS_MIN_DEED)


def total(state: list) -> int:
    return state[0] + state[1] + state[2]


def is_ring_candidate(state: list) -> bool:
    deed, echo, tenure, dead = state
    return total(state) >= RING_THRESHOLD and tenure >= RING_MIN_TENURE and not dead


# --- The helpers, from the ADR text alone ------------------------


def pooled_deed(accrual: int) -> int:
    return accrual // 4


def mutual_echo(budget: int) -> int:
    return budget // 10


def echo_contribution(witness_deed: int, budget: int) -> int:
    weight = witness_weight([witness_deed, 0, 0, False])
    return budget * weight // 1_000


def capped_echo_gain(contributions: list[int]) -> int:
    return min(sum(contributions), ECHO_TARGET_CAP)


# --- The draw, from the ADR text alone ---------------------------
#
# Weighted linear draw without replacement over the live pool: at
# each seat the next word selects the candidate whose cumulative
# weight covers r = word mod total. Zero-weight candidates are
# never drawn; a pool that falls to zero total weight stops the
# draw. An empty candidate list draws nothing; a pool with no
# weight at all is an error.


def draw(candidates: list[tuple[bytes, int]], entropy: bytes, seats: int):
    for first, second in zip(candidates, candidates[1:]):
        if not first[0] < second[0]:
            raise ValueError("UnsortedCandidates")
    if not candidates:
        return []
    live = sum(weight for _, weight in candidates)
    if live == 0:
        raise ValueError("EmptyPool")
    pool = list(range(len(candidates)))
    words = word_stream(entropy, seats)
    drawn: list[int] = []
    word_index = 0
    while len(drawn) < seats and pool and live > 0:
        word = words[word_index]
        word_index += 1
        r = word % live
        cumulative = 0
        selected = len(pool) - 1
        for position, index in enumerate(pool):
            cumulative += candidates[index][1]
            if r < cumulative:
                selected = position
                break
        index = pool.pop(selected)
        live -= candidates[index][1]
        drawn.append(index)
    return drawn


# --- Vector construction -----------------------------------------


def state_vector(name, initial, ops):
    """Replays the operations and records the state after each."""
    state = list(initial)
    after_each = []
    for op in ops:
        if op[0] == "era":
            state = advance_era(state, op[1], op[2])
        elif op[0] == "fraud":
            state = convict_fraud(state)
        elif op[0] == "witness":
            state = penalize_witness(state)
        elif op[0] == "sponsor":
            state = penalize_sponsor(state)
        elif op[0] == "strip":
            state = strip(state)
        else:
            raise AssertionError(f"unknown operation {op[0]}")
        after_each.append(list(state))
    return {
        "name": name,
        "initial": list(initial),
        "ops": [encode_op(op) for op in ops],
        "after_each": after_each,
        "final": list(state),
        "total": total(state),
        "witness_weight": witness_weight(state),
        "is_ring_candidate": is_ring_candidate(state),
    }


def encode_op(op) -> dict:
    """One operation as a flat object: a plain struct the Rust
    side deserializes without any tagged-enum machinery."""
    if op[0] == "era":
        return {"op": "era", "deed_gain": op[1], "echo_gain": op[2]}
    return {"op": op[0]}


def build_state_vectors(lcg: Lcg) -> list[dict]:
    vectors = [
        state_vector(
            "a fresh identity grows and saturates",
            [0, 0, 0, False],
            [["era", 2_200, 0], ["era", 5_000, 300], ["era", 40_000, 30_000]],
        ),
        state_vector(
            "a layer at zero with no gain stays at zero",
            [50, 40, 0, False],
            [["era", 0, 0], ["era", 90, 40], ["era", 0, 0]],
        ),
        state_vector(
            "a dead tenure layer never grows again",
            [10_000, 5_000, 12_000, False],
            [
                ["era", 0, 0],
                ["fraud"],
                ["era", 500, 100],
                ["era", 2_000, 1_000],
                ["era", 0, 0],
            ],
        ),
        state_vector(
            "the sanctions saturate at zero",
            [2_000, 0, 0, False],
            [["witness"], ["witness"], ["era", 50, 0]],
        ),
        state_vector(
            "a sponsor is heavier than a witness",
            [4_000, 0, 0, False],
            [["sponsor"], ["era", 0, 0]],
        ),
        state_vector(
            "the stripping takes everything",
            [40_000, 30_000, 30_000, False],
            [["strip"], ["era", 5_000, 2_000]],
        ),
        state_vector(
            "the wall of time, from below and from above",
            [40_000, 29_999, 14_999, False],
            [
                ["era", 100, 50],
                ["era", 100, 50],
                ["era", 100, 50],
                ["era", 100, 50],
            ],
        ),
        state_vector(
            "a dead layer cannot sit even with the score",
            [40_000, 30_000, 20_000, True],
            [["era", 100, 50], ["era", 100, 50]],
        ),
        state_vector(
            "an elder crosses the threshold honestly",
            [38_000, 12_000, 10_000, False],
            [
                ["era", 2_000, 1_000],
                ["era", 2_000, 1_000],
                ["era", 2_000, 1_000],
                ["era", 2_000, 1_000],
                ["era", 2_000, 1_000],
            ],
        ),
        state_vector(
            "fraud halves the deed and empties the echo",
            [39_999, 29_999, 15_000, False],
            [["fraud"], ["era", 3_000, 1_500]],
        ),
        state_vector(
            "the witness weight crosses its floor exactly",
            [19_999, 0, 0, False],
            [
                ["era", 1, 0],
                ["era", 4_000, 0],
                ["era", 16_000, 0],
                ["era", 16_000, 0],
            ],
        ),
    ]
    # Random walks: five identities, twelve eras each, sanctions
    # sprinkled in, gains drawn by the LCG. These exercise the
    # state machine far from the crafted boundaries.
    for walk in range(5):
        state = [
            lcg.next_below(20_000),
            lcg.next_below(10_000),
            lcg.next_below(20_000),
            False,
        ]
        if total(state) > 100_000 or state[2] > TENURE_MAX or state[1] > ECHO_MAX:
            state = [1_000, 500, 2_000, False]
        ops = []
        for _era in range(12):
            roll = lcg.next_below(100)
            if roll < 8:
                ops.append(["fraud"])
            elif roll < 16:
                ops.append(["witness"])
            elif roll < 20:
                ops.append(["sponsor"])
            elif roll < 22:
                ops.append(["strip"])
            else:
                ops.append(["era", lcg.next_below(12_000), lcg.next_below(3_000)])
        vectors.append(state_vector(f"random walk {walk}", state, ops))
    return vectors


def build_helper_vectors(lcg: Lcg) -> dict:
    pooled = [[2_500, 625], [3, 0], [40_000, 10_000], [1, 0], [999, 249]]
    pooled += [[lcg.next_below(50_000), 0] for _ in range(10)]
    pooled = [[value, pooled_deed(value)] for value, _ in pooled]
    mutual = [[1_000, 100], [9, 0], [10, 1], [99, 9]]
    mutual += [[lcg.next_below(2_000), 0] for _ in range(8)]
    mutual = [[value, mutual_echo(value)] for value, _ in mutual]
    # echo_contribution over the full weight range: below the floor
    # (zero), at the floor, mid, top, with several budgets.
    contributions = []
    for deed in (0, 19_999, 20_000, 25_000, 30_000, 40_000):
        for budget in (0, 1, 50, 100, 1_000):
            contributions.append([deed, budget, echo_contribution(deed, budget)])
    # capped_echo_gain: empty, under, exact, over, and a monster.
    caps = [
        [[], 0],
        [[100 for _ in range(19)], 1_900],
        [[100 for _ in range(20)], 2_000],
        [[100 for _ in range(21)], ECHO_TARGET_CAP],
        [[4_000_000], ECHO_TARGET_CAP],
        [[1, 1, 1], 3],
        [[2_000, 1], ECHO_TARGET_CAP],
    ]
    for _ in range(6):
        contribs = [lcg.next_below(500) for _ in range(lcg.next_below(12) + 1)]
        caps.append([contribs, 0])
    caps = [[contribs, capped_echo_gain(contribs)] for contribs, _ in caps]
    return {
        "pooled_deed": pooled,
        "mutual_echo": mutual,
        "echo_contribution": contributions,
        "capped_echo_gain": caps,
    }


def build_draw_vectors(lcg: Lcg) -> tuple[list[dict], list[dict]]:
    vectors = []
    # A full pool of sixty candidates, fifty-five seats: the shape
    # of a real era draw.
    ids = lcg.distinct_sorted(60)
    pool = [[ids[i], 70_000 + lcg.next_below(30_000)] for i in range(60)]
    entropy = lcg.bytes(32)
    vectors.append(
        {
            "name": "a full era draw, sixty candidates, fifty-five seats",
            "candidates": [[i.hex(), w] for i, w in pool],
            "entropy_hex": entropy.hex(),
            "seats": 55,
            "drawn": draw(pool, entropy, 55),
        }
    )
    # Equal weights: the draw must still cover distinct candidates.
    ids = lcg.distinct_sorted(70)
    pool = [[i, 80_000] for i in ids]
    entropy = lcg.bytes(24)
    vectors.append(
        {
            "name": "equal weights draw distinct candidates",
            "candidates": [[i.hex(), w] for i, w in pool],
            "entropy_hex": entropy.hex(),
            "seats": 70,
            "drawn": draw(pool, entropy, 70),
        }
    )
    # A short pool draws every candidate.
    ids = lcg.distinct_sorted(3)
    pool = [[ids[0], 90_000], [ids[1], 85_000], [ids[2], 70_000]]
    entropy = b"short pool entropy"
    vectors.append(
        {
            "name": "a short pool draws every candidate",
            "candidates": [[i.hex(), w] for i, w in pool],
            "entropy_hex": entropy.hex(),
            "seats": 55,
            "drawn": draw(pool, entropy, 55),
        }
    )
    # A whale of zero weight among established candidates is never
    # drawn.
    ids = lcg.distinct_sorted(4)
    pool = [[ids[0], 0], [ids[1], 70_000], [ids[2], 70_000], [ids[3], 0]]
    entropy = b"whale entropy"
    vectors.append(
        {
            "name": "zero-weight whales are never drawn",
            "candidates": [[i.hex(), w] for i, w in pool],
            "entropy_hex": entropy.hex(),
            "seats": 2,
            "drawn": draw(pool, entropy, 2),
        }
    )
    # One weighted candidate: the draw exhausts the weight and
    # stops, never dividing by zero.
    ids = lcg.distinct_sorted(3)
    pool = [[ids[0], 90_000], [ids[1], 0], [ids[2], 0]]
    entropy = b"exhaust entropy"
    vectors.append(
        {
            "name": "a pool that falls to zero weight stops drawing",
            "candidates": [[i.hex(), w] for i, w in pool],
            "entropy_hex": entropy.hex(),
            "seats": 3,
            "drawn": draw(pool, entropy, 3),
        }
    )
    # A one-candidate pool draws it.
    ids = lcg.distinct_sorted(1)
    pool = [(ids[0], 100)]
    vectors.append(
        {
            "name": "a single candidate draws itself",
            "candidates": [[i.hex(), w] for i, w in pool],
            "entropy_hex": b"one".hex(),
            "seats": 55,
            "drawn": draw(pool, b"one", 55),
        }
    )
    # Several random pools of assorted sizes.
    for i in range(6):
        count = 5 + lcg.next_below(40)
        ids = lcg.distinct_sorted(count)
        pool = [
            [ident, (0 if lcg.next_below(8) == 0 else 70_000 + lcg.next_below(30_000))]
            for ident in ids
        ]
        seats = 1 + lcg.next_below(count + 10)
        entropy = lcg.bytes(1 + lcg.next_below(40))
        vectors.append(
            {
                "name": f"random pool {i}",
                "candidates": [[ident.hex(), w] for ident, w in pool],
                "entropy_hex": entropy.hex(),
                "seats": seats,
                "drawn": draw(pool, entropy, seats),
            }
        )
    rejected = [
        {
            "name": "a pool with no weight at all",
            "candidates": [[i.hex(), 0] for i in lcg.distinct_sorted(3)],
            "seats": 2,
            "error": "EmptyPool",
        },
        {
            "name": "candidates not strictly ascending",
            "candidates": [[bytes([7] * 32).hex(), 70_000], [bytes([7] * 32).hex(), 70_000]],
            "seats": 2,
            "error": "UnsortedCandidates",
        },
        {
            "name": "descending candidates",
            "candidates": [
                [bytes([9] * 32).hex(), 70_000],
                [bytes([3] * 32).hex(), 70_000],
            ],
            "seats": 2,
            "error": "UnsortedCandidates",
        },
    ]
    return vectors, rejected


def build_word_stream_vectors(lcg: Lcg) -> list[dict]:
    vectors = []
    for entropy in (b"", b"entropy", b"a", lcg.bytes(32), lcg.bytes(7)):
        count = 12
        words = word_stream(entropy, count)
        vectors.append(
            {
                "entropy_hex": entropy.hex(),
                "count": count,
                "words_hex": [format(word, "032x") for word in words],
            }
        )
    return vectors


def main() -> None:
    lcg = Lcg(16180339)
    vectors = {
        "format": 1,
        "comment": (
            "ANTUMBRA kleos cross-validation vectors, generated by "
            "code/scripts/gen_kleos_vectors.py (independent Python "
            "implementation of ADR-003 and ADR-015). Regenerate with "
            "the generator; both implementations must agree bit for bit."
        ),
        "word_stream": build_word_stream_vectors(lcg),
        "state": build_state_vectors(lcg),
        "helpers": build_helper_vectors(lcg),
    }
    draw_vectors, draw_rejected = build_draw_vectors(lcg)
    vectors["draw"] = draw_vectors
    vectors["draw_rejected"] = draw_rejected

    # Self-checks: the generator verifies its own invariants before
    # writing anything.
    for vector in vectors["state"]:
        state = vector["final"]
        assert 0 <= state[0] <= DEED_MAX, "deed bound"
        assert 0 <= state[1] <= ECHO_MAX, "echo bound"
        assert 0 <= state[2] <= TENURE_MAX, "tenure bound"
        assert len(vector["after_each"]) == len(vector["ops"]), "one state per op"
    for vector in vectors["draw"]:
        drawn = vector["drawn"]
        assert len(drawn) == len(set(drawn)), "no replacement"
        for index in drawn:
            assert 0 <= index < len(vector["candidates"]), "index in range"
        # Replaying the draw must reproduce it exactly.
        pool = [(bytes.fromhex(pair[0]), pair[1]) for pair in vector["candidates"]]
        replay = draw(pool, bytes.fromhex(vector["entropy_hex"]), vector["seats"])
        assert replay == drawn, "the draw is deterministic"
    for vector in vectors["word_stream"]:
        assert len(vector["words_hex"]) == vector["count"], "word count"
        assert word_stream(bytes.fromhex(vector["entropy_hex"]), vector["count"]) == [
            int(word, 16) for word in vector["words_hex"]
        ], "the stream is deterministic"
    for vector in draw_rejected:
        pool = [(bytes.fromhex(pair[0]), pair[1]) for pair in vector["candidates"]]
        try:
            draw(pool, b"entropy", vector["seats"])
        except ValueError as error:
            assert str(error) == vector["error"], "the rejection reason matches"
        else:
            raise AssertionError(f"the pool must be rejected ({vector['name']})")

    OUTPUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
    print(
        f"{len(vectors['state'])} state vectors, "
        f"{len(vectors['draw'])} draws, "
        f"{len(vectors['draw_rejected'])} rejections, "
        f"{len(vectors['word_stream'])} word streams"
    )


if __name__ == "__main__":
    main()
