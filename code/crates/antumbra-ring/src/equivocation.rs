//! The stripping evidence: a seat that signed a competing fork
//! (ADR-002, ADR-014).
//!
//! The sanction of the Ring falls on the only thing a validator
//! owns that is precious: its Kleos, reset to zero. The evidence
//! is self-contained and verifiable by any node without trusting
//! its source: the seat, and two signatures of that seat over
//! two different messages of the same era and the same
//! sequence. The canonical encoding:
//!
//! ```text
//! seat:u16 LE | first message | first signature:64B
//! | second message | second signature:64B
//! ```

use antumbra_primitives::keys::verify as verify_ed25519;
use antumbra_primitives::{Reader, Signature, Writer};

use crate::error::RingError;
use crate::message::CheckpointMessage;
use crate::roster::Roster;

/// The evidence that a seat signed a competing fork.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Equivocation {
    seat: u16,
    first: CheckpointMessage,
    first_signature: Signature,
    second: CheckpointMessage,
    second_signature: Signature,
}

impl Equivocation {
    /// Assembles the evidence; verification is
    /// [`Equivocation::verify`].
    #[must_use]
    pub const fn new(
        seat: u16,
        first: CheckpointMessage,
        first_signature: Signature,
        second: CheckpointMessage,
        second_signature: Signature,
    ) -> Self {
        Self {
            seat,
            first,
            first_signature,
            second,
            second_signature,
        }
    }

    /// The seat that signed twice.
    #[must_use]
    pub const fn seat(&self) -> u16 {
        self.seat
    }

    /// The first message.
    #[must_use]
    pub const fn first(&self) -> &CheckpointMessage {
        &self.first
    }

    /// The second message.
    #[must_use]
    pub const fn second(&self) -> &CheckpointMessage {
        &self.second
    }

    /// Verifies the evidence against the roster of the era: the
    /// seat is held, both eras match the roster, the sequences
    /// match, the messages differ, and both signatures verify
    /// under the roster key of the seat.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] naming the first violated rule.
    /// A valid evidence is consensus data: the reputation layer
    /// consumes it to reset the score of the seat.
    pub fn verify(&self, roster: &Roster) -> Result<(), RingError> {
        let key = roster.key(self.seat).ok_or(RingError::SeatOutOfRange {
            seat: self.seat,
            seats: roster.len(),
        })?;
        if roster.era() != self.first.era() {
            return Err(RingError::EraMismatch {
                roster: roster.era(),
                message: self.first.era(),
            });
        }
        if roster.era() != self.second.era() {
            return Err(RingError::EraMismatch {
                roster: roster.era(),
                message: self.second.era(),
            });
        }
        if self.first.sequence() != self.second.sequence() {
            return Err(RingError::DifferentSequence {
                first: self.first.sequence(),
                second: self.second.sequence(),
            });
        }
        if self.first == self.second {
            return Err(RingError::IdenticalMessages);
        }
        if !verify_ed25519(&self.first_signature, &self.first.encode(), key) {
            return Err(RingError::InvalidSignature { seat: self.seat });
        }
        if !verify_ed25519(&self.second_signature, &self.second.encode(), key) {
            return Err(RingError::InvalidSignature { seat: self.seat });
        }
        Ok(())
    }

    /// The canonical encoding: the seat, the first message and
    /// its signature, the second message and its signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u16(self.seat);
        let mut out = w.finish();
        out.extend_from_slice(&self.first.encode());
        out.extend_from_slice(&self.first_signature.0);
        out.extend_from_slice(&self.second.encode());
        out.extend_from_slice(&self.second_signature.0);
        out
    }

    /// Strictly decodes the evidence from its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] describing the first violation
    /// found.
    pub fn decode(bytes: &[u8]) -> Result<Self, RingError> {
        let mut r = Reader::new(bytes);
        let seat = r.read_u16()?;
        let first = CheckpointMessage::read(&mut r)?;
        let first_signature = Signature(r.read_array::<64>()?);
        let second = CheckpointMessage::read(&mut r)?;
        let second_signature = Signature(r.read_array::<64>()?);
        r.finish()?;
        Ok(Self::new(
            seat,
            first,
            first_signature,
            second,
            second_signature,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antumbra_primitives::Hash;

    fn seeds() -> Vec<[u8; 32]> {
        (1..=55u8).map(|i| [i; 32]).collect()
    }

    fn roster(era: u64) -> Roster {
        let keys = seeds()
            .iter()
            .map(|s| antumbra_primitives::KeyPair::spend(s).public())
            .collect();
        Roster::new(era, keys).expect("the roster builds")
    }

    fn message(era: u64, sequence: u64, tip: u8) -> CheckpointMessage {
        CheckpointMessage::new(era, sequence, Hash([tip; 32]), Hash([9u8; 32]))
    }

    fn signed(seat: usize, message: &CheckpointMessage) -> Signature {
        antumbra_primitives::KeyPair::spend(&seeds()[seat]).sign(&message.encode())
    }

    #[test]
    fn a_competing_fork_strips_the_seat() {
        let first = message(3, 100, 1);
        let second = message(3, 100, 2);
        let first_signature = signed(7, &first);
        let second_signature = signed(7, &second);
        let evidence = Equivocation::new(7, first, first_signature, second, second_signature);
        assert_eq!(evidence.verify(&roster(3)), Ok(()));
        // The encoding roundtrips.
        let bytes = evidence.encode();
        let decoded = Equivocation::decode(&bytes).expect("the evidence decodes");
        assert_eq!(decoded, evidence);
    }

    #[test]
    fn one_message_twice_is_not_a_fork() {
        let first = message(3, 100, 1);
        let first_signature = signed(7, &first);
        let second_signature = signed(7, &first);
        let evidence =
            Equivocation::new(7, first.clone(), first_signature, first, second_signature);
        assert_eq!(
            evidence.verify(&roster(3)),
            Err(RingError::IdenticalMessages)
        );
    }

    #[test]
    fn two_sequences_are_not_a_fork() {
        let first = message(3, 100, 1);
        let second = message(3, 101, 2);
        let first_signature = signed(7, &first);
        let second_signature = signed(7, &second);
        let evidence = Equivocation::new(7, first, first_signature, second, second_signature);
        assert!(matches!(
            evidence.verify(&roster(3)),
            Err(RingError::DifferentSequence { .. })
        ));
    }

    #[test]
    fn two_eras_are_not_a_fork() {
        let first = message(3, 100, 1);
        let second = message(4, 100, 2);
        let first_signature = signed(7, &first);
        let second_signature = signed(7, &second);
        let evidence = Equivocation::new(7, first, first_signature, second, second_signature);
        assert!(matches!(
            evidence.verify(&roster(3)),
            Err(RingError::EraMismatch { .. })
        ));
    }

    #[test]
    fn a_foreign_signature_is_rejected() {
        let first = message(3, 100, 1);
        let second = message(3, 100, 2);
        let first_signature = signed(8, &first);
        let second_signature = signed(7, &second);
        let evidence = Equivocation::new(7, first, first_signature, second, second_signature);
        assert!(matches!(
            evidence.verify(&roster(3)),
            Err(RingError::InvalidSignature { seat: 7 })
        ));
    }

    #[test]
    fn an_unknown_seat_is_rejected() {
        let first = message(3, 100, 1);
        let second = message(3, 100, 2);
        let first_signature = signed(0, &first);
        let second_signature = signed(0, &second);
        let evidence = Equivocation::new(90, first, first_signature, second, second_signature);
        assert!(matches!(
            evidence.verify(&roster(3)),
            Err(RingError::SeatOutOfRange { seat: 90, .. })
        ));
    }
}
