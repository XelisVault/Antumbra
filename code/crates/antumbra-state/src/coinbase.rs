//! The emission calendar and the coinbase arithmetic (ADR-024).
//!
//! The cap, the eclipse emissions and the per-block rewards are
//! integer arithmetic, exactly reproducible in any language: the
//! eclipse table is the archived calendar of ADR-007, proven two
//! ways — by the integer closed form of `floor(E0 * R^n)` and by
//! the archived float script (`simulations/emission.py`) — and the
//! per-slot reward is the quotient-remainder spread that closes
//! each eclipse, and the cap, atom for atom.
//!
//! The slot of a block is its position in the consensus order: the
//! genesis is slot 0 and mints nothing. Two blocks may share a
//! height; no two blocks share a slot, which keeps the emission
//! unique over any DAG shape.

use antumbra_primitives::hash::keccak256;
use antumbra_primitives::{Address, KeyPair, Network};

/// The monetary cap, in atomic units: 16,180,339 ATU (ADR-007).
pub const CAP_ATOMIC: u64 = 16_180_339 * 100_000_000;

/// The blocks per eclipse: four years of two-second blocks, the
/// calendar year of 365.25 days.
pub const BLOCKS_PER_ECLIPSE: u64 = 63_115_200;

/// The number of eclipses of the calendar: thirty-four, the last
/// absorbing the remainder to the cap.
pub const ECLIPSES: usize = 34;

/// The first emission, in whole ATU: 6,180,340.
pub const E0_ATU: u64 = 6_180_340;

/// The treasury takes 6.18% of each reward for the first eight
/// eclipses: the numerator over 10,000.
pub const TREASURY_NUMERATOR: u64 = 618;
/// The denominator of the treasury share.
pub const TREASURY_DENOMINATOR: u64 = 10_000;

/// The eclipses during which the treasury is paid (ADR-007: for
/// eight eclipses, extinguished automatically afterward).
pub const TREASURY_ECLIPSES: u64 = 8;

/// The maturity of coinbase outputs, in slots: ten, the depth of
/// the proof-of-work fallback of ADR-002.
pub const MATURITY: u64 = 10;

/// The archived eclipse emissions, in whole ATU (ADR-007, ADR-024).
///
/// The first thirty-three values are `floor(E0 * R^n)` with
/// `R = (sqrt(5) - 1) / 2`; the thirty-fourth absorbs the remainder
/// so the sum equals the cap exactly. `calendar_closes_on_the_cap`
/// proves this table against the integer closed form; the Python
/// generator recomputes it independently over the archived vector
/// set.
pub const ECLIPSE_EMISSIONS_ATU: [u64; ECLIPSES] = [
    6_180_340, 3_819_660, 2_360_679, 1_458_980, 901_699, 557_280, 344_418, 212_862, 131_556,
    81_306, 50_249, 31_056, 19_193, 11_862, 7_331, 4_531, 2_800, 1_730, 1_069, 661, 408, 252, 156,
    96, 59, 36, 22, 14, 8, 5, 3, 2, 1, 15,
];

/// The eclipse index of a slot: the genesis (slot 0) belongs to no
/// emission; slot 1 opens eclipse 0.
///
/// # Panics
///
/// Panics on slot 0 only through the subtraction underflow, which
/// callers prevent by never asking for the reward of the genesis.
#[must_use]
pub const fn eclipse_of_slot(slot: u64) -> u64 {
    (slot - 1) / BLOCKS_PER_ECLIPSE
}

/// The reward of a slot, in atomic units: the eclipse emission
/// spread over the eclipse, one extra atom on the first
/// `remainder` slots.
#[must_use]
pub fn reward_of_slot(slot: u64) -> u64 {
    if slot == 0 {
        return 0;
    }
    let eclipse = eclipse_of_slot(slot);
    let emission_atomic = ECLIPSE_EMISSIONS_ATU[eclipse as usize] * 100_000_000;
    let base = emission_atomic / BLOCKS_PER_ECLIPSE;
    let remainder = emission_atomic % BLOCKS_PER_ECLIPSE;
    let position = (slot - 1) % BLOCKS_PER_ECLIPSE;
    base + u64::from(position < remainder)
}

/// The treasury share of a reward, in atomic units: 6.18% rounded
/// down; the miner keeps the rest.
#[must_use]
pub const fn treasury_share_of(reward_atomic: u64) -> u64 {
    reward_atomic * TREASURY_NUMERATOR / TREASURY_DENOMINATOR
}

/// Whether the treasury is still paid at this slot: the first
/// `TREASURY_ECLIPSES` eclipses only.
#[must_use]
pub const fn treasury_active_at_slot(slot: u64) -> bool {
    slot >= 1 && eclipse_of_slot(slot) < TREASURY_ECLIPSES
}

/// The expected shape of the coinbase of a block at this slot:
/// the number of outputs, the treasury amount and the total
/// (reward plus the block fees the caller adds).
#[must_use]
pub fn expected_coinbase(slot: u64, block_fees_atomic: u64) -> (usize, u64, u64) {
    let reward = reward_of_slot(slot);
    let total = reward + block_fees_atomic;
    if treasury_active_at_slot(slot) {
        (2, treasury_share_of(reward), total)
    } else {
        (1, 0, total)
    }
}

/// The treasury address of the development network (ADR-024): the
/// two fixed seeds under Keccak-256, the devnet network byte. The
/// spend and view keys come from independent seeds: the treasury
/// address is not a single-seed wallet, the Ember chamber holds
/// the spending authority. The governance of the key belongs to
/// the chamber; the ledger only verifies the destination.
#[must_use]
pub fn devnet_treasury_address() -> Address {
    let spend =
        KeyPair::from_seed(keccak256(b"antumbra-treasury-spend-devnet").as_bytes()).public();
    let view = KeyPair::from_seed(keccak256(b"antumbra-treasury-view-devnet").as_bytes()).public();
    Address::new(Network::Devnet, spend, view)
}

/// The integer floor of `E0 * R^n` for `R = (sqrt(5) - 1) / 2`:
/// the exact Lucas-Fibonacci closed form, no floating point
/// anywhere.
///
/// `R = |psi|` with `psi = (1 - sqrt(5)) / 2` the conjugate of
/// phi, and `psi^n = (L(n) - sqrt(5) F(n)) / 2` with `F(n)` the
/// Fibonacci numbers and `L(n)` the Lucas numbers. The floor of
/// `(P + Q sqrt(5)) / 2` over integers is `(P + isqrt(5 Q^2)) / 2`
/// when `Q > 0` and `(S - 1) / 2` with `S = P - isqrt(5 Q^2)` when
/// `Q < 0`, the one-unit correction of the negative irrational
/// part. Every intermediate fits `u128` with four orders of
/// magnitude to spare for `n <= 33`.
#[must_use]
#[cfg(test)]
fn exact_eclipse_emission(n: u64) -> u64 {
    if n == 0 {
        return E0_ATU;
    }
    let (fib, lucas) = fibonacci_lucas(n);
    let e0 = E0_ATU as i128;
    // R^n = (-1)^n (L(n) - sqrt(5) F(n)) / 2, so E0 R^n = (P + Q
    // sqrt(5)) / 2 with the signs below.
    let (p, q) = if n % 2 == 0 {
        (e0 * lucas as i128, -(e0 * fib as i128))
    } else {
        (-(e0 * lucas as i128), e0 * fib as i128)
    };
    let q_abs = q.unsigned_abs();
    let root = isqrt_u128(5 * q_abs * q_abs);
    if q > 0 {
        let s = p + root as i128;
        u64::try_from(s / 2).expect("the emission is a positive u64")
    } else {
        let s = p - root as i128;
        u64::try_from((s - 1) / 2).expect("the emission is a positive u64")
    }
}

/// `(F(n), L(n))` by the plain Fibonacci and Lucas iterations.
#[cfg(test)]
fn fibonacci_lucas(n: u64) -> (u64, u64) {
    let (mut f_prev, mut f_curr) = (0u64, 1u64); // F(0), F(1)
    let (mut l_prev, mut l_curr) = (2u64, 1u64); // L(0), L(1)
    if n == 0 {
        return (f_prev, l_prev);
    }
    for _ in 1..n {
        let f_next = f_prev + f_curr;
        f_prev = f_curr;
        f_curr = f_next;
        let l_next = l_prev + l_curr;
        l_prev = l_curr;
        l_curr = l_next;
    }
    (f_curr, l_curr)
}

/// The integer square root of a `u128`, exact.
#[cfg(test)]
fn isqrt_u128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    // Newton's method from a power-of-two seed above the root:
    // the iteration decreases monotonically to the exact floor.
    let bits = 128 - n.leading_zeros();
    let mut x: u128 = 1u128 << bits.div_ceil(2);
    loop {
        let y = (x + n / x) / 2;
        if y >= x {
            break;
        }
        x = y;
    }
    x
}

/// The whole calendar, in whole ATU, as the ledger sees it: the
/// archived table.
#[must_use]
pub const fn calendar() -> &'static [u64; ECLIPSES] {
    &ECLIPSE_EMISSIONS_ATU
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_closes_on_the_cap() {
        let total: u64 = ECLIPSE_EMISSIONS_ATU.iter().sum();
        assert_eq!(
            total * 100_000_000,
            CAP_ATOMIC,
            "the calendar must close on the cap exactly"
        );
    }

    #[test]
    fn calendar_matches_the_integer_closed_form() {
        for (n, value) in ECLIPSE_EMISSIONS_ATU.iter().enumerate().take(33) {
            assert_eq!(
                exact_eclipse_emission(n as u64),
                *value,
                "eclipse {n} diverges from the exact closed form"
            );
        }
    }

    #[test]
    fn first_two_eclipses_sum_to_ten_million() {
        assert_eq!(
            ECLIPSE_EMISSIONS_ATU[0] + ECLIPSE_EMISSIONS_ATU[1],
            10_000_000
        );
    }

    #[test]
    fn slots_close_each_eclipse_exactly() {
        // The spread closes the eclipse by construction: B times the
        // base plus the remainder. Verified slot by slot on a small
        // synthetic calendar, and on the boundary positions of the
        // real first eclipse.
        for (e, emission) in ECLIPSE_EMISSIONS_ATU.iter().enumerate().take(3) {
            let emission_atomic = emission * 100_000_000;
            let base = emission_atomic / BLOCKS_PER_ECLIPSE;
            let remainder = emission_atomic % BLOCKS_PER_ECLIPSE;
            let first_slot = u64::try_from(e).expect("fits") * BLOCKS_PER_ECLIPSE + 1;
            // The boundary positions of the spread.
            assert_eq!(
                reward_of_slot(first_slot),
                base + 1,
                "eclipse {e}: first slot carries the remainder atom"
            );
            if remainder > 1 {
                assert_eq!(
                    reward_of_slot(first_slot + remainder - 1),
                    base + 1,
                    "eclipse {e}: the last remainder slot carries the atom"
                );
            }
            assert_eq!(
                reward_of_slot(first_slot + remainder),
                base,
                "eclipse {e}: the first slot after the remainder pays the base"
            );
            assert_eq!(
                reward_of_slot(first_slot + BLOCKS_PER_ECLIPSE - 1),
                base,
                "eclipse {e}: the last slot pays the base"
            );
        }
        // The closure itself, over the whole first eclipse, in one
        // arithmetic identity (the spread is a two-valued step
        // function of the position).
        let emission_atomic = ECLIPSE_EMISSIONS_ATU[0] * 100_000_000;
        let base = emission_atomic / BLOCKS_PER_ECLIPSE;
        let remainder = emission_atomic % BLOCKS_PER_ECLIPSE;
        assert_eq!(
            base * BLOCKS_PER_ECLIPSE + remainder,
            emission_atomic,
            "the identity the spread realizes"
        );
    }

    #[test]
    fn the_first_reward_is_the_archived_one() {
        // The archived initial reward: 9,792,158 atomic on the first
        // slots, the base 9,792,157 after the remainder run.
        assert_eq!(reward_of_slot(1), 9_792_158);
        assert_eq!(reward_of_slot(2), 9_792_158);
        assert_eq!(reward_of_slot(0), 0, "the genesis mints nothing");
    }

    #[test]
    fn treasury_windows_and_shares() {
        assert!(treasury_active_at_slot(1));
        assert!(treasury_active_at_slot(
            TREASURY_ECLIPSES * BLOCKS_PER_ECLIPSE
        ));
        assert!(!treasury_active_at_slot(
            TREASURY_ECLIPSES * BLOCKS_PER_ECLIPSE + 1
        ));
        let r = reward_of_slot(1);
        assert_eq!(treasury_share_of(r), r * 618 / 10_000);
        // 6.18% of the first reward, rounded down.
        assert_eq!(treasury_share_of(9_792_158), 605_155);
    }

    #[test]
    fn the_eclipse_boundary_reprices_the_reward() {
        // Slot B is the last slot of eclipse 0: the base, no
        // remainder atom (the remainder run is far shorter than the
        // eclipse). Slot B + 1 opens eclipse 1 at its own base.
        let last_of_zero = BLOCKS_PER_ECLIPSE;
        let first_of_one = BLOCKS_PER_ECLIPSE + 1;
        assert_eq!(reward_of_slot(last_of_zero), 9_792_157);
        let emission_one = ECLIPSE_EMISSIONS_ATU[1] * 100_000_000;
        let base_one = emission_one / BLOCKS_PER_ECLIPSE;
        let remainder_one = emission_one % BLOCKS_PER_ECLIPSE;
        assert_eq!(
            reward_of_slot(first_of_one),
            base_one + u64::from(remainder_one > 0),
            "the first slot of eclipse 1 carries its own remainder atom"
        );
        assert!(reward_of_slot(first_of_one) < reward_of_slot(1));
    }

    #[test]
    fn the_devnet_treasury_address_is_stable() {
        let first = devnet_treasury_address();
        let second = devnet_treasury_address();
        assert_eq!(first, second);
        assert_eq!(first.network(), Network::Devnet);
    }

    #[test]
    fn isqrt_is_exact_at_the_boundaries() {
        for n in [0u128, 1, 2, 3, 4, 8, 9, 15, 16, 1 << 100, (1 << 100) + 5] {
            let r = isqrt_u128(n);
            assert!(r * r <= n, "isqrt({n}) too large");
            assert!((r + 1) * (r + 1) > n, "isqrt({n}) too small");
        }
    }
}
