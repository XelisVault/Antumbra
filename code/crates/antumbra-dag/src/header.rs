//! The block header: the final container of the ordering layer
//! (ADR-013).
//!
//! The canonical encoding is the single serialized form of a
//! header:
//!
//! ```text
//! version:u16 LE | parent count:varint | parent id:32B *
//! | height:u64 LE | timestamp:u64 LE | nonce:u64 LE
//! | payload root:32B
//! ```
//!
//! Parents are strictly ascending by id and distinct: the encoding
//! is unique and block ids are non-malleable, exactly like the
//! sorted inputs of a transaction. The genesis block alone carries
//! the single zero hash as its parent (the zero hash is never a
//! block id: every real id is the Keccak-256 of a non-empty
//! encoding, and the convention closes the "parent of the genesis"
//! question without a special case in the decoding rules). The
//! block id is Keccak-256 of the canonical encoding.
//!
//! The height is one plus the maximum parent height and is
//! verified at insertion; it is announced rather than derived so
//! that headers-first synchronization can sanity-check a header
//! before its parents arrive.

use antumbra_primitives::{keccak256, Hash, Reader, Writer};

use crate::error::DagError;

/// The header version of the ordering layer.
pub const VERSION_1: u16 = 1;

/// The maximum number of parents a block may reference (ADR-013).
pub const MAX_PARENTS: usize = 16;

/// A block header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    version: u16,
    parents: Vec<Hash>,
    height: u64,
    timestamp: u64,
    nonce: u64,
    payload_root: Hash,
}

impl Header {
    /// Builds a version 1 header.
    ///
    /// Construction runs no validation: [`Header::decode`] enforces
    /// the canonical form and the DAG insertion the network rules,
    /// so that a miner can assemble a header incrementally before
    /// it becomes checkable.
    #[must_use]
    pub fn new(
        parents: Vec<Hash>,
        height: u64,
        timestamp: u64,
        nonce: u64,
        payload_root: Hash,
    ) -> Self {
        Self {
            version: VERSION_1,
            parents,
            height,
            timestamp,
            nonce,
            payload_root,
        }
    }

    /// The genesis header: the zero parent, height zero, a nonce of
    /// zero, and the payload root of the genesis transaction list.
    #[must_use]
    pub fn genesis(timestamp: u64, payload_root: Hash) -> Self {
        Self::new(vec![Hash::ZERO], 0, timestamp, 0, payload_root)
    }

    /// The header version; always 1 in this crate.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// The parent ids, strictly ascending, as announced.
    #[must_use]
    pub fn parents(&self) -> &[Hash] {
        &self.parents
    }

    /// The height announced in the header.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// The timestamp, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// The mining nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The Keccak-256 commitment over the canonical transaction id
    /// list of this block.
    #[must_use]
    pub const fn payload_root(&self) -> Hash {
        self.payload_root
    }

    /// The canonical encoding, the single serialized form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u16(self.version);
        w.write_varint(self.parents.len() as u64);
        for parent in &self.parents {
            w.write_array(parent.as_bytes());
        }
        w.write_u64(self.height);
        w.write_u64(self.timestamp);
        w.write_u64(self.nonce);
        w.write_array(self.payload_root.as_bytes());
        w.finish()
    }

    /// The block id: Keccak-256 of the canonical encoding.
    #[must_use]
    pub fn id(&self) -> Hash {
        keccak256(&self.encode())
    }

    /// Reads a header from an open reader, leaving it positioned
    /// after the header. Shared with the block decoder so that the
    /// block encoding is exactly the header encoding followed by
    /// the payload, never a second, divergent form.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DagError> {
        let version = r.read_u16()?;
        if version != VERSION_1 {
            return Err(DagError::InvalidVersion(version));
        }
        let count = r.read_varint()?;
        if count == 0 {
            return Err(DagError::NoParents);
        }
        if count > MAX_PARENTS as u64 {
            return Err(DagError::TooManyParents(count as usize));
        }
        let mut parents = Vec::new();
        for _ in 0..count {
            parents.push(Hash(r.read_array::<32>()?));
        }
        for pair in parents.windows(2) {
            if pair[0] >= pair[1] {
                return Err(DagError::UnsortedParents);
            }
        }
        let height = r.read_u64()?;
        let timestamp = r.read_u64()?;
        let nonce = r.read_u64()?;
        let payload_root = Hash(r.read_array::<32>()?);
        Ok(Self::new(parents, height, timestamp, nonce, payload_root))
    }

    /// Strictly decodes a header from its canonical bytes.
    ///
    /// Non-canonical parent order, structural limit violations and
    /// trailing bytes are errors: a decoder must never normalize
    /// what the encoder could not have produced.
    ///
    /// # Errors
    ///
    /// Returns a [`DagError`] describing the first violation found.
    pub fn decode(bytes: &[u8]) -> Result<Self, DagError> {
        let mut r = Reader::new(bytes);
        let header = Self::read(&mut r)?;
        r.finish()?;
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        let parents = vec![Hash([1u8; 32]), Hash([2u8; 32]), Hash([3u8; 32])];
        Header::new(parents, 7, 1_750_000_000_000, 42, Hash([9u8; 32]))
    }

    #[test]
    fn the_roundtrip_is_exact() {
        let header = sample();
        let bytes = header.encode();
        let decoded = Header::decode(&bytes).expect("the sample decodes");
        assert_eq!(decoded, header);
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn the_id_is_keccak_of_the_encoding() {
        let header = sample();
        assert_eq!(header.id(), keccak256(&header.encode()));
    }

    #[test]
    fn unsorted_parents_are_rejected() {
        // Descending parents are not strictly ascending.
        let header = Header::new(vec![Hash([3u8; 32]), Hash([1u8; 32])], 7, 1, 1, Hash::ZERO);
        let bytes = header.encode();
        assert_eq!(Header::decode(&bytes), Err(DagError::UnsortedParents));
    }

    #[test]
    fn duplicate_parents_are_rejected() {
        let header = Header::new(vec![Hash([5u8; 32]), Hash([5u8; 32])], 7, 1, 1, Hash::ZERO);
        assert_eq!(
            Header::decode(&header.encode()),
            Err(DagError::UnsortedParents)
        );
    }

    #[test]
    fn too_many_parents_are_rejected() {
        let parents: Vec<Hash> = (0..=MAX_PARENTS as u8).map(|i| Hash([i; 32])).collect();
        let header = Header::new(parents, 7, 1, 1, Hash::ZERO);
        let expected = DagError::TooManyParents(MAX_PARENTS + 1);
        assert_eq!(Header::decode(&header.encode()), Err(expected));
    }

    #[test]
    fn a_header_without_parents_is_rejected() {
        // A parentless header is malformed, so it is manufactured
        // directly: version 1, parent count zero, nothing else.
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&VERSION_1.to_le_bytes());
        malformed.push(0u8);
        assert_eq!(Header::decode(&malformed), Err(DagError::NoParents));
    }

    #[test]
    fn a_wrong_version_is_rejected() {
        let mut bytes = sample().encode();
        bytes[0] = 2;
        assert_eq!(Header::decode(&bytes), Err(DagError::InvalidVersion(2)));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(matches!(Header::decode(&bytes), Err(DagError::Decode(_))));
    }

    #[test]
    fn the_genesis_carries_the_zero_parent() {
        let genesis = Header::genesis(1_750_000_000_000, Hash::ZERO);
        assert_eq!(genesis.parents(), &[Hash::ZERO]);
        assert_eq!(genesis.height(), 0);
        assert_eq!(genesis.nonce(), 0);
        assert!(Header::decode(&genesis.encode()).is_ok());
    }
}
