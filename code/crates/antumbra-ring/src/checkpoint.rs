//! A checkpoint: the message plus the seat signatures
//! (ADR-014).
//!
//! The canonical encoding is the message encoding followed by
//! the collected signatures:
//!
//! ```text
//! message | signature count:varint | (seat:u16 LE, signature:64B) *
//! ```
//!
//! The seats are strictly ascending and distinct: one seat
//! signs one checkpoint once. Thirty-seven valid signatures
//! (the quorum) finalize everything the message covers; the
//! verification of a signature is against the roster of the
//! message era alone, never against a source that relayed it.

use antumbra_primitives::keys::verify as verify_ed25519;
use antumbra_primitives::{KeyPair, Reader, Signature, Writer};

use crate::error::RingError;
use crate::message::CheckpointMessage;
use crate::roster::{Roster, SEATS};

/// One seat signature, as collected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeatSignature {
    seat: u16,
    signature: Signature,
}

impl SeatSignature {
    /// The seat that signed.
    #[must_use]
    pub const fn seat(&self) -> u16 {
        self.seat
    }

    /// The signature of the seat over the message encoding.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
}

/// A checkpoint under collection or verification.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    message: CheckpointMessage,
    signatures: Vec<SeatSignature>,
}

impl Checkpoint {
    /// Opens a checkpoint on a message, with no signature yet.
    #[must_use]
    pub const fn new(message: CheckpointMessage) -> Self {
        Self {
            message,
            signatures: Vec::new(),
        }
    }

    /// The message under signature.
    #[must_use]
    pub const fn message(&self) -> &CheckpointMessage {
        &self.message
    }

    /// The collected signatures, strictly ascending by seat.
    #[must_use]
    pub fn signatures(&self) -> &[SeatSignature] {
        &self.signatures
    }

    /// The number of signatures collected.
    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Whether the quorum is reached, signatures apart: the
    /// caller verifies them with [`Checkpoint::verify`] first.
    /// A checkpoint with quorum reached and verified signatures
    /// finalizes everything its message covers.
    #[must_use]
    pub fn is_final(&self) -> bool {
        self.signatures.len() >= crate::roster::QUORUM
    }

    /// Verifies and reports the quorum in one call: the
    /// signatures against the roster, then the count.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] naming the first violated rule;
    /// `Ok(false)` means verified but below the quorum.
    pub fn finalized(&self, roster: &Roster) -> Result<bool, RingError> {
        self.verify(roster)?;
        Ok(self.is_final())
    }

    /// Signs the message for a seat with the seat key pair and
    /// collects the signature.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] if the seat already signed this
    /// checkpoint or the seat count is exceeded.
    pub fn sign(&mut self, seat: u16, keypair: &KeyPair) -> Result<(), RingError> {
        if self.signatures.len() >= SEATS {
            return Err(RingError::TooManySignatures(self.signatures.len() + 1));
        }
        if self.signatures.iter().any(|s| s.seat == seat) {
            return Err(RingError::DuplicateSeat(seat));
        }
        let signature = keypair.sign(&self.message.encode());
        self.signatures.push(SeatSignature { seat, signature });
        Ok(())
    }

    /// Verifies every signature against the roster of the
    /// message era.
    ///
    /// The roster must govern the era of the message; every seat
    /// must be held; every signature must verify under the
    /// roster key of its seat.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] naming the first violated rule.
    pub fn verify(&self, roster: &Roster) -> Result<(), RingError> {
        if roster.era() != self.message.era() {
            return Err(RingError::EraMismatch {
                roster: roster.era(),
                message: self.message.era(),
            });
        }
        for collected in &self.signatures {
            let key = roster
                .key(collected.seat)
                .ok_or(RingError::SeatOutOfRange {
                    seat: collected.seat,
                    seats: roster.len(),
                })?;
            if !verify_ed25519(&collected.signature, &self.message.encode(), key) {
                return Err(RingError::InvalidSignature {
                    seat: collected.seat,
                });
            }
        }
        Ok(())
    }

    /// The canonical encoding: the message, then the strictly
    /// ascending seat signatures.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.message.encode();
        let mut w = Writer::new();
        w.write_varint(self.signatures.len() as u64);
        for collected in &self.signatures {
            w.write_u16(collected.seat);
            w.write_array(&collected.signature.0);
        }
        out.extend_from_slice(&w.finish());
        out
    }

    /// Strictly decodes a checkpoint from its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] describing the first violation
    /// found.
    pub fn decode(bytes: &[u8]) -> Result<Self, RingError> {
        let mut r = Reader::new(bytes);
        let message = CheckpointMessage::read(&mut r)?;
        let count = r.read_varint()?;
        if count > SEATS as u64 {
            return Err(RingError::TooManySignatures(count as usize));
        }
        let mut signatures: Vec<SeatSignature> = Vec::new();
        for _ in 0..count {
            let seat = r.read_u16()?;
            let signature = Signature(r.read_array::<64>()?);
            for previous in &signatures {
                if previous.seat == seat {
                    return Err(RingError::DuplicateSeat(seat));
                }
            }
            if let Some(last) = signatures.last() {
                if last.seat > seat {
                    return Err(RingError::UnsortedSeats);
                }
            }
            signatures.push(SeatSignature { seat, signature });
        }
        r.finish()?;
        Ok(Self {
            message,
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::QUORUM;
    use antumbra_primitives::Hash;

    fn seeds(n: u8) -> Vec<[u8; 32]> {
        (1..=n).map(|i| [i; 32]).collect()
    }

    fn full_roster(era: u64) -> Roster {
        let keys = seeds(55)
            .iter()
            .map(|s| antumbra_primitives::KeyPair::spend(s).public())
            .collect();
        Roster::new(era, keys).expect("the full roster builds")
    }

    fn message(era: u64, sequence: u64) -> CheckpointMessage {
        CheckpointMessage::new(era, sequence, Hash([7u8; 32]), Hash([9u8; 32]))
    }

    #[test]
    fn a_quorum_of_signatures_finalizes() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        for seat in 0..QUORUM as u16 {
            checkpoint
                .sign(seat, &KeyPair::spend(&seeds(55)[usize::from(seat)]))
                .expect("signs");
        }
        assert_eq!(checkpoint.signature_count(), QUORUM);
        assert!(checkpoint.is_final());
        assert_eq!(checkpoint.finalized(&full_roster(1)), Ok(true));
        // The encoding roundtrips exactly.
        let bytes = checkpoint.encode();
        let decoded = Checkpoint::decode(&bytes).expect("the checkpoint decodes");
        assert_eq!(decoded, checkpoint);
    }

    #[test]
    fn below_the_quorum_does_not_finalize() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        for seat in 0..(QUORUM - 1) as u16 {
            checkpoint
                .sign(seat, &KeyPair::spend(&seeds(55)[usize::from(seat)]))
                .expect("signs");
        }
        assert!(!checkpoint.is_final());
        assert_eq!(checkpoint.finalized(&full_roster(1)), Ok(false));
    }

    #[test]
    fn a_seat_signs_once() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        checkpoint
            .sign(3, &KeyPair::spend(&seeds(55)[3]))
            .expect("signs");
        assert_eq!(
            checkpoint.sign(3, &KeyPair::spend(&seeds(55)[3])),
            Err(RingError::DuplicateSeat(3))
        );
    }

    #[test]
    fn a_wrong_roster_era_is_rejected() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        checkpoint
            .sign(0, &KeyPair::spend(&seeds(55)[0]))
            .expect("signs");
        assert!(matches!(
            checkpoint.verify(&full_roster(2)),
            Err(RingError::EraMismatch { .. })
        ));
    }

    #[test]
    fn a_foreign_key_is_rejected() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        // Seat 0 signs with the key of seat 1: the signature
        // does not verify under the key of seat 0.
        checkpoint
            .sign(0, &KeyPair::spend(&seeds(55)[1]))
            .expect("signs");
        assert!(matches!(
            checkpoint.verify(&full_roster(1)),
            Err(RingError::InvalidSignature { seat: 0 })
        ));
    }

    #[test]
    fn an_out_of_range_seat_is_rejected() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        checkpoint
            .sign(60, &KeyPair::spend(&[9u8; 32]))
            .expect("signs");
        assert!(matches!(
            checkpoint.verify(&full_roster(1)),
            Err(RingError::SeatOutOfRange { seat: 60, .. })
        ));
    }

    #[test]
    fn unsorted_seats_are_rejected() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        checkpoint
            .sign(5, &KeyPair::spend(&seeds(55)[5]))
            .expect("signs");
        checkpoint
            .sign(2, &KeyPair::spend(&seeds(55)[2]))
            .expect("signs");
        let bytes = checkpoint.encode();
        assert_eq!(Checkpoint::decode(&bytes), Err(RingError::UnsortedSeats));
    }

    #[test]
    fn duplicated_seats_are_rejected() {
        let mut checkpoint = Checkpoint::new(message(1, 1));
        checkpoint
            .sign(4, &KeyPair::spend(&seeds(55)[4]))
            .expect("signs");
        let bytes = checkpoint.encode();
        // The message, then two copies of the same pair under a
        // count of two: manufactured, never produced by a signer.
        let pair = &bytes[bytes.len() - 66..];
        let message_len = bytes.len() - 67;
        let mut duplicated = bytes[..message_len].to_vec();
        duplicated.push(2);
        duplicated.extend_from_slice(pair);
        duplicated.extend_from_slice(pair);
        assert_eq!(
            Checkpoint::decode(&duplicated),
            Err(RingError::DuplicateSeat(4))
        );
    }
}
