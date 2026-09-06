//! The Ring draw of an era: deterministic, weighted (ADR-002,
//! ADR-015).
//!
//! The fifty-five seats are drawn each era among the candidates
//! of the reputation layer, weighted linearly by their Kleos
//! total: `P(i) = K_i / sum(K)`. The draw is without
//! replacement, seeded by an entropy string the chain commits:
//! the order root of the last finalized checkpoint of the
//! previous era.
//!
//! The entropy is stretched into a word stream,
//! `word(i) = the first sixteen bytes, little endian, of
//! Keccak-256(entropy || u64_le(i))`, and at each seat the next
//! word `u` selects the candidate whose cumulative weight covers
//! `r = u mod total`. The modulo bias is bounded by
//! `total / 2^128`, below 2^-100 for any reachable pool:
//! smaller than the rounding of the simulation that specified
//! the rules. Zero-weight candidates are never drawn; an empty
//! total is an error, never a panic.

use antumbra_primitives::{keccak256, Hash};

use crate::error::KleosError;

/// The entropy word stream of a draw: Keccak-256 over the
/// entropy and a monotonically increasing counter, sixteen
/// little-endian bytes at a time.
pub struct WordStream<'a> {
    entropy: &'a [u8],
    counter: u64,
    word: [u8; 32],
    used: usize,
}

impl<'a> WordStream<'a> {
    /// Opens the stream on an entropy string.
    #[must_use]
    pub const fn new(entropy: &'a [u8]) -> Self {
        Self {
            entropy,
            counter: 0,
            word: [0u8; 32],
            used: 32,
        }
    }

    fn refill(&mut self) {
        let mut block = Vec::with_capacity(self.entropy.len() + 8);
        block.extend_from_slice(self.entropy);
        block.extend_from_slice(&self.counter.to_le_bytes());
        self.word = keccak256(&block).0;
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }

    /// The next word: the first sixteen unread bytes of the
    /// stream, little endian. One Keccak block carries two
    /// words; the next block is hashed on demand.
    #[must_use]
    pub fn next_word(&mut self) -> u128 {
        if self.used + 16 > 32 {
            self.refill();
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.word[self.used..self.used + 16]);
        self.used += 16;
        u128::from_le_bytes(bytes)
    }
}

/// Draws the seats of an era.
///
/// The candidates are `(identity, weight)` pairs, strictly
/// ascending by identity and pairwise distinct; the weights are
/// the Kleos totals. The draw consumes `seats` seats (or every
/// candidate when fewer exist), without replacement, and returns
/// the indices of the drawn candidates in draw order.
///
/// # Errors
///
/// Returns a [`KleosError`] if the pool holds no weight at all
/// or the candidates are not strictly ascending.
pub fn draw(
    candidates: &[(Hash, u32)],
    entropy: &[u8],
    seats: usize,
) -> Result<Vec<usize>, KleosError> {
    for pair in candidates.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(KleosError::UnsortedCandidates);
        }
    }
    let mut pool: Vec<usize> = (0..candidates.len()).collect();
    let mut total: u64 = candidates.iter().map(|(_, w)| u64::from(*w)).sum();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    if total == 0 {
        return Err(KleosError::EmptyPool);
    }
    let mut stream = WordStream::new(entropy);
    let mut drawn = Vec::with_capacity(seats.min(candidates.len()));
    // A pool that falls to zero total weight can draw nothing
    // more: the remaining candidates weigh nothing, and a modulo
    // by zero is a panic, never a consensus behavior.
    while drawn.len() < seats && !pool.is_empty() && total > 0 {
        let word = stream.next_word();
        let r = (word % u128::from(total)) as u64;
        let mut cumulative: u64 = 0;
        let mut selected = pool.len() - 1;
        for (position, index) in pool.iter().enumerate() {
            cumulative += u64::from(candidates[*index].1);
            if r < cumulative {
                selected = position;
                break;
            }
        }
        let index = pool.remove(selected);
        total -= u64::from(candidates[index].1);
        drawn.push(index);
    }
    Ok(drawn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::Kleos;

    fn candidate(seed: u8, weight: u32) -> (Hash, u32) {
        (Hash([seed; 32]), weight)
    }

    fn sorted(mut pool: Vec<(Hash, u32)>) -> Vec<(Hash, u32)> {
        pool.sort_unstable_by_key(|candidate| candidate.0);
        pool
    }

    #[test]
    fn the_word_stream_is_deterministic() {
        let mut first = WordStream::new(b"entropy");
        let mut second = WordStream::new(b"entropy");
        let mut other = WordStream::new(b"entropz");
        for _ in 0..10 {
            let a = first.next_word();
            assert_eq!(a, second.next_word());
            assert_ne!(a, other.next_word());
        }
    }

    #[test]
    fn the_draw_is_deterministic_and_ordered() {
        let pool: Vec<(Hash, u32)> = sorted((1..=60u8).map(|i| candidate(i, 80_000)).collect());
        let seats = draw(&pool, b"era entropy", 55).expect("the draw runs");
        assert_eq!(seats.len(), 55);
        let again = draw(&pool, b"era entropy", 55).expect("the draw runs");
        assert_eq!(seats, again);
        // A different entropy draws a different cohort, most of
        // the time.
        let other = draw(&pool, b"other entropy", 55).expect("the draw runs");
        assert_ne!(seats, other);
        // Every seat is a distinct candidate.
        let mut unique = seats.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), seats.len());
    }

    #[test]
    fn a_short_pool_draws_every_candidate() {
        let pool = sorted(vec![candidate(1, 90_000), candidate(2, 85_000)]);
        let seats = draw(&pool, b"entropy", 55).expect("the draw runs");
        assert_eq!(seats.len(), 2);
        let mut covered: Vec<usize> = seats;
        covered.sort_unstable();
        assert_eq!(covered, vec![0, 1]);
    }

    #[test]
    fn the_weights_lead_the_draw() {
        // A whale of zero weight among established candidates is
        // never drawn.
        let pool = sorted(vec![
            candidate(1, 0),
            candidate(2, 70_000),
            candidate(3, 70_000),
        ]);
        let seats = draw(&pool, b"entropy", 2).expect("the draw runs");
        assert_eq!(seats.len(), 2);
        assert!(!seats.contains(&0), "a zero weight is never drawn");
    }

    #[test]
    fn an_empty_or_weightless_pool_is_rejected() {
        assert_eq!(draw(&[], b"entropy", 5), Ok(Vec::new()));
        let pool = sorted(vec![candidate(1, 0), candidate(2, 0)]);
        assert_eq!(draw(&pool, b"entropy", 2), Err(KleosError::EmptyPool));
    }

    #[test]
    fn unsorted_candidates_are_rejected() {
        // Same identity twice: not strictly ascending.
        let pool = vec![candidate(7, 70_000), candidate(7, 70_000)];
        assert_eq!(
            draw(&pool, b"entropy", 2),
            Err(KleosError::UnsortedCandidates)
        );
    }

    #[test]
    fn a_pool_that_falls_to_zero_weight_stops_drawing() {
        // One weighted candidate followed by a whale of zero
        // weight: the draw exhausts the weight and stops, never
        // dividing by zero.
        let pool = sorted(vec![candidate(1, 90_000), candidate(2, 0), candidate(3, 0)]);
        let seats = draw(&pool, b"entropy", 3).expect("the draw runs");
        assert_eq!(seats, vec![0]);
    }

    #[test]
    fn the_stream_survives_many_draws() {
        // Sixty candidates, fifty-five seats: the stream provides
        // every word without repetition drift.
        let pool: Vec<(Hash, u32)> = sorted(
            (1..=60u8)
                .map(|i| {
                    let state = Kleos::from_parts(40_000, 30_000, 20_000, false).expect("bounds");
                    candidate(i, state.total())
                })
                .collect(),
        );
        let seats = draw(&pool, &[0u8; 32], 55).expect("the draw runs");
        assert_eq!(seats.len(), 55);
    }
}
