//! The checkpoint message: what a seat signs (ADR-014).
//!
//! The canonical encoding is the single serialized form, and it
//! is the signing message itself: a seat signs these bytes, a
//! notary verifies against them without holding the DAG.
//!
//! ```text
//! version:u16 LE (1) | era:u64 LE | sequence:u64 LE
//! | tip:32B | order root:32B
//! ```
//!
//! The tip is the block id the checkpoint notarizes and the
//! order root is the canonical list hash of the consensus order
//! of that tip: the checkpoint signs the order, not a bare
//! block, so a notary verifies exactly what the ledger will
//! consume. Eras and sequences are counted from one; the tip is
//! never the zero hash.

use antumbra_primitives::{keccak256, Hash, Reader, Writer};

use crate::error::RingError;

/// The message version of the finality layer.
pub const VERSION_1: u16 = 1;

/// A checkpoint message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckpointMessage {
    era: u64,
    sequence: u64,
    tip: Hash,
    order_root: Hash,
}

impl CheckpointMessage {
    /// Builds a version 1 checkpoint message.
    ///
    /// Construction runs no validation: [`CheckpointMessage::decode`]
    /// enforces the canonical form. The zero era, the zero
    /// sequence and the zero tip are rejected there.
    #[must_use]
    pub const fn new(era: u64, sequence: u64, tip: Hash, order_root: Hash) -> Self {
        Self {
            era,
            sequence,
            tip,
            order_root,
        }
    }

    /// The era of the checkpoint; eras are six months of
    /// protocol time, counted from one.
    #[must_use]
    pub const fn era(&self) -> u64 {
        self.era
    }

    /// The sequence of the checkpoint within its era, counted
    /// from one; checkpoints come every four seconds.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The tip block id the checkpoint notarizes.
    #[must_use]
    pub const fn tip(&self) -> Hash {
        self.tip
    }

    /// The canonical list hash of the consensus order of the
    /// tip: the value the ordering layer computes and the
    /// checkpoint commits.
    #[must_use]
    pub const fn order_root(&self) -> Hash {
        self.order_root
    }

    /// The canonical encoding, which is also the signing
    /// message: the bytes every seat signature covers.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u16(VERSION_1);
        w.write_u64(self.era);
        w.write_u64(self.sequence);
        w.write_array(self.tip.as_bytes());
        w.write_array(self.order_root.as_bytes());
        w.finish()
    }

    /// The digest of the encoding, for storage and indexing.
    #[must_use]
    pub fn digest(&self) -> Hash {
        keccak256(&self.encode())
    }

    /// Reads a message from an open reader, leaving it
    /// positioned after the message. Shared with the checkpoint
    /// and the stripping evidence decoders.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, RingError> {
        let version = r.read_u16()?;
        if version != VERSION_1 {
            return Err(RingError::InvalidVersion(version));
        }
        let era = r.read_u64()?;
        if era == 0 {
            return Err(RingError::EraZero);
        }
        let sequence = r.read_u64()?;
        if sequence == 0 {
            return Err(RingError::SequenceZero);
        }
        let tip = Hash(r.read_array::<32>()?);
        if tip == Hash::ZERO {
            return Err(RingError::ZeroTip);
        }
        let order_root = Hash(r.read_array::<32>()?);
        Ok(Self::new(era, sequence, tip, order_root))
    }

    /// Strictly decodes a message from its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] describing the first violation
    /// found.
    pub fn decode(bytes: &[u8]) -> Result<Self, RingError> {
        let mut r = Reader::new(bytes);
        let message = Self::read(&mut r)?;
        r.finish()?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CheckpointMessage {
        CheckpointMessage::new(3, 42, Hash([7u8; 32]), Hash([9u8; 32]))
    }

    #[test]
    fn the_roundtrip_is_exact() {
        let message = sample();
        let bytes = message.encode();
        let decoded = CheckpointMessage::decode(&bytes).expect("the sample decodes");
        assert_eq!(decoded, message);
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn the_digest_is_keccak_of_the_encoding() {
        assert_eq!(sample().digest(), keccak256(&sample().encode()));
    }

    #[test]
    fn a_zero_era_is_rejected() {
        let message = CheckpointMessage::new(0, 1, Hash([7u8; 32]), Hash([9u8; 32]));
        assert_eq!(
            CheckpointMessage::decode(&message.encode()),
            Err(RingError::EraZero)
        );
    }

    #[test]
    fn a_zero_sequence_is_rejected() {
        let message = CheckpointMessage::new(1, 0, Hash([7u8; 32]), Hash([9u8; 32]));
        assert_eq!(
            CheckpointMessage::decode(&message.encode()),
            Err(RingError::SequenceZero)
        );
    }

    #[test]
    fn a_zero_tip_is_rejected() {
        let message = CheckpointMessage::new(1, 1, Hash::ZERO, Hash([9u8; 32]));
        assert_eq!(
            CheckpointMessage::decode(&message.encode()),
            Err(RingError::ZeroTip)
        );
    }

    #[test]
    fn a_wrong_version_is_rejected() {
        let mut bytes = sample().encode();
        bytes[0] = 2;
        assert_eq!(
            CheckpointMessage::decode(&bytes),
            Err(RingError::InvalidVersion(2))
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(matches!(
            CheckpointMessage::decode(&bytes),
            Err(RingError::Decode(_))
        ));
    }
}
