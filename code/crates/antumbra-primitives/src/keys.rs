//! Ed25519 keys and signatures.
//!
//! Ed25519 (RFC 8032) carries the transparent sphere: mandates,
//! checkpoints, the Ring, agent registration. The private sphere
//! (one-time addresses, ring signatures) arrives with the Veil
//! crate and will use the same curve arithmetic.
//!
//! Verification is strict everywhere: non-canonical encodings and
//! small-order points are rejected, because a consensus verifier
//! must never accept a form the encoder could never produce.

use core::fmt;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;

use crate::hash::keccak256;

/// A 32-byte Ed25519 secret seed.
#[derive(Clone)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    /// The view seed derived from a spend seed: Keccak-256 of the
    /// seed. One phrase, two deterministic keys, the CryptoNote
    /// lineage pattern.
    #[must_use]
    pub fn derive_view_seed(spend_seed: &[u8; 32]) -> Self {
        Self(keccak256(spend_seed).0)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Secrets never enter logs or debug output.
        write!(f, "SecretKey(REDACTED)")
    }
}

/// A 32-byte Ed25519 public key (compressed point).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Restores a public key from its compressed encoding.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DecodeError::InvalidAddress`] if the 32
    /// bytes are not a valid canonical curve point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, crate::DecodeError> {
        match VerifyingKey::from_bytes(bytes) {
            Ok(_) => Ok(Self(*bytes)),
            Err(_) => Err(crate::DecodeError::InvalidAddress),
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// An Ed25519 key pair.
#[derive(Clone)]
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    /// Builds the key pair from a 32-byte seed, per RFC 8032.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let public = *VerifyingKey::from(&signing).as_bytes();
        Self {
            secret: SecretKey(*seed),
            public: PublicKey(public),
        }
    }

    /// The spend key pair derived from `seed`.
    #[must_use]
    pub fn spend(seed: &[u8; 32]) -> Self {
        Self::from_seed(seed)
    }

    /// The view key pair derived from the same `seed`.
    #[must_use]
    pub fn view(seed: &[u8; 32]) -> Self {
        Self::from_seed(&SecretKey::derive_view_seed(seed).0)
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// The secret seed. Handle with care: this spends funds.
    #[must_use]
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Signs a message.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let signing = SigningKey::from_bytes(&self.secret.0);
        Signature(signing.sign(message).to_bytes())
    }
}

/// Strictly verifies an Ed25519 signature.
#[must_use]
pub fn verify(signature: &Signature, message: &[u8], public: &PublicKey) -> bool {
    let Ok(verifying) = VerifyingKey::from_bytes(&public.0) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    verifying.verify_strict(message, &sig).is_ok()
}

/// Constant-time equality of two byte slices (key comparisons).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032, section 7.1, test vectors 1 and 2.
    const RFC8032_T1_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_T1_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const RFC8032_T1_SIG: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];
    const RFC8032_T2_SEED: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    const RFC8032_T2_PUBLIC: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];
    const RFC8032_T2_MSG: [u8; 1] = [0x72];
    const RFC8032_T2_SIG: [u8; 64] = [
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00,
    ];

    #[test]
    fn rfc8032_test_1() {
        let kp = KeyPair::from_seed(&RFC8032_T1_SEED);
        assert_eq!(kp.public(), PublicKey(RFC8032_T1_PUBLIC));
        let sig = kp.sign(b"");
        assert_eq!(sig, Signature(RFC8032_T1_SIG));
        assert!(verify(&sig, b"", &kp.public()));
    }

    #[test]
    fn rfc8032_test_2() {
        let kp = KeyPair::from_seed(&RFC8032_T2_SEED);
        assert_eq!(kp.public(), PublicKey(RFC8032_T2_PUBLIC));
        let sig = kp.sign(&RFC8032_T2_MSG);
        assert_eq!(sig, Signature(RFC8032_T2_SIG));
        assert!(verify(&sig, &RFC8032_T2_MSG, &kp.public()));
    }

    #[test]
    fn tampered_message_rejected() {
        let kp = KeyPair::from_seed(&RFC8032_T2_SEED);
        let sig = kp.sign(&RFC8032_T2_MSG);
        assert!(!verify(&sig, b"q", &kp.public()));
    }

    #[test]
    fn tampered_signature_rejected() {
        let kp = KeyPair::from_seed(&RFC8032_T2_SEED);
        let mut bytes = kp.sign(&RFC8032_T2_MSG).0;
        bytes[0] ^= 0x01;
        let sig = Signature(bytes);
        assert!(!verify(&sig, &RFC8032_T2_MSG, &kp.public()));
    }

    #[test]
    fn wrong_public_key_rejected() {
        let kp = KeyPair::from_seed(&RFC8032_T2_SEED);
        let sig = kp.sign(&RFC8032_T2_MSG);
        let other = KeyPair::from_seed(&RFC8032_T1_SEED);
        assert!(!verify(&sig, &RFC8032_T2_MSG, &other.public()));
    }

    #[test]
    fn view_derivation_is_keccak_of_seed() {
        let seed = [7u8; 32];
        let view = KeyPair::view(&seed);
        assert_eq!(
            view.public(),
            KeyPair::from_seed(&keccak256(&seed).0).public()
        );
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let kp = KeyPair::from_seed(&[9u8; 32]);
        let formatted = format!("{:?}", kp.secret());
        assert!(formatted.contains("REDACTED"));
        assert!(!formatted.contains("0909"));
    }
}
