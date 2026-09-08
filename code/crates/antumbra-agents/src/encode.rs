//! The uniform authority encoding: no field ever splits the
//! anonymity set (C10 closed).

use crate::error::AgentError;
use antumbra_primitives::{keccak256, Hash};

/// The fixed width of the authority field of every transaction,
/// human and agent alike.
pub const AUTHORITY_BYTES: usize = 64;

/// The domain-separation prefix of the padding derivation.
const PAD_PREFIX: &[u8] = b"antumbra-authority";

/// The authority of a transaction: who is allowed to move this
/// value.
///
/// A human spends through a stealth commitment; an agent spends
/// through the root of its Warrant. **Both encode to the same
/// sixty-four bytes with the same internal structure**: the
/// first half is the payload (the stealth commitment or the
/// warrant root), the second half is `keccak256("antumbra-
/// authority" || payload)`. The derivation is identical for
/// both kinds, so the shape of the field tells an observer
/// nothing about the nature of the spender. The human is not
/// the empty bit, the agent is not a tagged bit: they are the
/// same width, the same derivation, the same silence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Authority {
    /// A human spend: the payload is the stealth commitment.
    Human {
        /// The stealth commitment of the human spender.
        stealth: Hash,
    },
    /// An agent spend: the payload is the Warrant root.
    Agent {
        /// The root of the Warrant that spends.
        warrant_root: Hash,
    },
}

impl Authority {
    /// The payload half: stealth commitment or warrant root.
    #[must_use]
    pub const fn payload(&self) -> Hash {
        match *self {
            Self::Human { stealth } => stealth,
            Self::Agent { warrant_root } => warrant_root,
        }
    }

    /// The padding half, derived the same way for both kinds.
    #[must_use]
    pub fn pad(&self) -> Hash {
        derive_pad(&self.payload())
    }

    /// The uniform sixty-four-byte encoding: payload, then the
    /// derived padding.
    #[must_use]
    pub fn encode(&self) -> [u8; AUTHORITY_BYTES] {
        let mut out = [0u8; AUTHORITY_BYTES];
        out[..32].copy_from_slice(&self.payload().0);
        out[32..].copy_from_slice(&self.pad().0);
        out
    }

    /// Checks that a sixty-four-byte authority field is well
    /// formed: the second half must derive from the first.
    ///
    /// The check is kind-blind on purpose: it validates the
    /// shape without saying whether the spender is a human or
    /// an agent. What proves the authority is the signature
    /// witness, not the field.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::MalformedAuthority`] when the
    /// padding does not derive from the payload.
    pub fn well_formed(bytes: &[u8; AUTHORITY_BYTES]) -> Result<Hash, AgentError> {
        let mut payload = [0u8; 32];
        let mut pad = [0u8; 32];
        payload.copy_from_slice(&bytes[..32]);
        pad.copy_from_slice(&bytes[32..]);
        if derive_pad(&Hash(payload)) != Hash(pad) {
            return Err(AgentError::MalformedAuthority);
        }
        Ok(Hash(payload))
    }
}

/// The shared derivation: `keccak256(prefix || payload)`.
fn derive_pad(payload: &Hash) -> Hash {
    let mut material = Vec::with_capacity(PAD_PREFIX.len() + 32);
    material.extend_from_slice(PAD_PREFIX);
    material.extend_from_slice(&payload.0);
    keccak256(&material)
}
