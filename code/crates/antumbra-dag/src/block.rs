//! A block: one header plus the transaction ids it orders
//! (ADR-013).
//!
//! The canonical encoding is the header encoding followed by the
//! payload:
//!
//! ```text
//! header | tx id count:varint | tx id:32B *
//! ```
//!
//! The transaction ids are strictly ascending and distinct, at
//! most sixty-four of them, so the encoding is unique. The payload
//! root of the header is Keccak-256 of the payload alone (varint
//! count then the ids): a header commits its transactions without
//! carrying them, which is what headers-first synchronization
//! consumes. The block id stays the Keccak-256 of the header
//! encoding, exactly as announced.
//!
//! The ledger rules (do these ids exist, are they unspent, is a
//! double spend resolved) consume the consensus order downstream;
//! the ordering layer only orders.

use antumbra_primitives::{keccak256, Hash, Reader, Writer};

use crate::error::DagError;
use crate::header::Header;

/// The maximum number of transactions a block may order (ADR-013).
pub const MAX_TXS: usize = 64;

/// The payload root: Keccak-256 of the canonical transaction id
/// list, the varint count followed by the ids.
#[must_use]
pub fn payload_root(tx_ids: &[Hash]) -> Hash {
    let mut w = Writer::new();
    w.write_varint(tx_ids.len() as u64);
    for id in tx_ids {
        w.write_array(id.as_bytes());
    }
    keccak256(&w.finish())
}

/// A block of the ordering layer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    header: Header,
    tx_ids: Vec<Hash>,
}

impl Block {
    /// Builds a block from a header and its transaction ids.
    ///
    /// Construction runs no validation: [`Block::decode`] enforces
    /// the canonical form and the DAG insertion the network rules.
    /// A block whose header root does not commit its payload is
    /// rejected by both, never silently accepted.
    #[must_use]
    pub fn new(header: Header, tx_ids: Vec<Hash>) -> Self {
        Self { header, tx_ids }
    }

    /// The development network genesis: timestamp
    /// 1,750,000,000,000 (2025-06-15T15:06:40Z), nonce zero, empty
    /// payload. The id of this exact block is archived in the
    /// cross vector set: two implementations, one genesis.
    #[must_use]
    pub fn devnet_genesis() -> Self {
        let root = payload_root(&[]);
        Self::new(
            Header::genesis(crate::dag::GENESIS_TIMESTAMP_MS, root),
            Vec::new(),
        )
    }

    /// The header of the block.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The transaction ids this block orders, strictly ascending.
    #[must_use]
    pub fn tx_ids(&self) -> &[Hash] {
        &self.tx_ids
    }

    /// The block id, the Keccak-256 of the header encoding.
    #[must_use]
    pub fn id(&self) -> Hash {
        self.header.id()
    }

    /// The canonical encoding, the single serialized form: the
    /// header encoding followed by the payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header.encode();
        let mut w = Writer::new();
        w.write_varint(self.tx_ids.len() as u64);
        for id in &self.tx_ids {
            w.write_array(id.as_bytes());
        }
        out.extend_from_slice(&w.finish());
        out
    }

    /// Strictly decodes a block from its canonical bytes.
    ///
    /// Structural limit violations, unsorted transaction ids, a
    /// payload root that does not commit the announced ids, and
    /// trailing bytes are all errors.
    ///
    /// # Errors
    ///
    /// Returns a [`DagError`] describing the first violation found.
    pub fn decode(bytes: &[u8]) -> Result<Self, DagError> {
        let mut r = Reader::new(bytes);
        let header = Header::read(&mut r)?;
        let count = r.read_varint()?;
        if count > MAX_TXS as u64 {
            return Err(DagError::TooManyTransactions(count as usize));
        }
        let mut tx_ids = Vec::new();
        for _ in 0..count {
            tx_ids.push(Hash(r.read_array::<32>()?));
        }
        for pair in tx_ids.windows(2) {
            if pair[0] >= pair[1] {
                return Err(DagError::UnsortedTransactions);
            }
        }
        r.finish()?;
        let computed = payload_root(&tx_ids);
        if computed != header.payload_root() {
            return Err(DagError::PayloadRootMismatch {
                announced: header.payload_root(),
                computed,
            });
        }
        Ok(Self::new(header, tx_ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Block {
        let tx_ids = vec![Hash([1u8; 32]), Hash([2u8; 32])];
        let header = Header::new(
            vec![Hash::ZERO],
            1,
            1_750_000_000_000,
            7,
            payload_root(&tx_ids),
        );
        Block::new(header, tx_ids)
    }

    #[test]
    fn the_roundtrip_is_exact() {
        let block = sample();
        let bytes = block.encode();
        let decoded = Block::decode(&bytes).expect("the sample decodes");
        assert_eq!(decoded, block);
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn the_id_covers_the_payload_through_the_root() {
        let block = sample();
        let id = block.id();
        // The id commits the header, and the header commits the
        // payload through the root: a payload change without a
        // root change cannot survive the canonical decode.
        assert_eq!(id, keccak256(&block.header().encode()));
        let mismatched = Block::new(
            Header::new(
                vec![Hash::ZERO],
                1,
                1,
                7,
                payload_root(&[Hash([1u8; 32]), Hash([3u8; 32])]),
            ),
            vec![Hash([1u8; 32]), Hash([2u8; 32])],
        );
        let bytes = mismatched.encode();
        assert!(matches!(
            Block::decode(&bytes),
            Err(DagError::PayloadRootMismatch { .. })
        ));
    }

    #[test]
    fn unsorted_transaction_ids_are_rejected() {
        let tx_ids = vec![Hash([2u8; 32]), Hash([1u8; 32])];
        let header = Header::new(vec![Hash::ZERO], 1, 1, 7, payload_root(&tx_ids));
        let bytes = Block::new(header, tx_ids).encode();
        assert_eq!(Block::decode(&bytes), Err(DagError::UnsortedTransactions));
    }

    #[test]
    fn too_many_transaction_ids_are_rejected() {
        let tx_ids: Vec<Hash> = (0..=MAX_TXS as u8).map(|i| Hash([i; 32])).collect();
        let header = Header::new(vec![Hash::ZERO], 1, 1, 7, payload_root(&tx_ids));
        let bytes = Block::new(header, tx_ids).encode();
        let expected = DagError::TooManyTransactions(MAX_TXS + 1);
        assert_eq!(Block::decode(&bytes), Err(expected));
    }

    #[test]
    fn the_genesis_block_is_the_archived_one() {
        let genesis = Block::devnet_genesis();
        assert!(genesis.tx_ids().is_empty());
        assert_eq!(genesis.header().parents(), &[Hash::ZERO]);
        let decoded = Block::decode(&genesis.encode()).expect("the genesis decodes");
        assert_eq!(decoded, genesis);
    }
}
