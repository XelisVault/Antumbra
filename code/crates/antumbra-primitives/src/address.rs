//! Address format: network byte, spend key, view key, checksum.
//!
//! An address is the base58 block encoding of 69 bytes: one network
//! byte, the 32-byte spend public key, the 32-byte view public key,
//! and the first four bytes of Keccak-256 over the preceding 65
//! bytes. A mistyped character breaks the checksum; a transposition
//! breaks the block structure. Network bytes are ASCII mnemonic:
//! `A` mainnet, `T` testnet, `D` development network. Their final
//! values are frozen by the genesis ADR and never changed after.

use core::fmt;
use core::str::FromStr;

use crate::base58::{base58_decode, base58_encode};
use crate::hash::keccak256;
use crate::keys::PublicKey;
use crate::DecodeError;

/// The network an address belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

impl Network {
    /// The network byte of an address.
    #[must_use]
    pub const fn prefix(self) -> u8 {
        match self {
            Self::Mainnet => b'A',
            Self::Testnet => b'T',
            Self::Devnet => b'D',
        }
    }

    /// Restores the network from an address network byte.
    #[must_use]
    pub const fn from_prefix(prefix: u8) -> Option<Self> {
        match prefix {
            b'A' => Some(Self::Mainnet),
            b'T' => Some(Self::Testnet),
            b'D' => Some(Self::Devnet),
            _ => None,
        }
    }
}

/// The length of the raw address bytes: 1 + 32 + 32 + 4.
const RAW_LEN: usize = 69;

/// The length of the checksum: 1 + 32 + 32 bytes are checksummed.
const CHECKSUMMED_LEN: usize = 65;

/// An ANTUMBRA address: a network, a spend key, a view key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    network: Network,
    spend: PublicKey,
    view: PublicKey,
}

impl Address {
    /// Builds an address from its parts.
    #[must_use]
    pub const fn new(network: Network, spend: PublicKey, view: PublicKey) -> Self {
        Self {
            network,
            spend,
            view,
        }
    }

    /// The network of the address.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// The spend public key.
    #[must_use]
    pub const fn spend(&self) -> PublicKey {
        self.spend
    }

    /// The view public key.
    #[must_use]
    pub const fn view(&self) -> PublicKey {
        self.view
    }

    /// The four-byte checksum over prefix, spend and view keys.
    #[must_use]
    fn checksum(&self) -> [u8; 4] {
        let mut buf = [0u8; CHECKSUMMED_LEN];
        buf[0] = self.network.prefix();
        buf[1..33].copy_from_slice(&self.spend.0);
        buf[33..65].copy_from_slice(&self.view.0);
        let digest = keccak256(&buf).0;
        [digest[0], digest[1], digest[2], digest[3]]
    }

    /// The 69 raw bytes: prefix, spend, view, checksum.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; RAW_LEN] {
        let mut buf = [0u8; RAW_LEN];
        buf[0] = self.network.prefix();
        buf[1..33].copy_from_slice(&self.spend.0);
        buf[33..65].copy_from_slice(&self.view.0);
        buf[65..69].copy_from_slice(&self.checksum());
        buf
    }

    /// Decodes the 69 raw bytes back into an address.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InvalidAddress`] on a wrong length,
    /// an unknown network byte or a checksum mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != RAW_LEN {
            return Err(DecodeError::InvalidAddress);
        }
        let network = Network::from_prefix(bytes[0]).ok_or(DecodeError::InvalidAddress)?;
        let spend =
            PublicKey::from_bytes(bytes[1..33].try_into().expect("slice 1..33 has 32 bytes"))?;
        let view =
            PublicKey::from_bytes(bytes[33..65].try_into().expect("slice 33..65 has 32 bytes"))?;
        let candidate = Self {
            network,
            spend,
            view,
        };
        if candidate.checksum() != bytes[65..69] {
            return Err(DecodeError::InvalidAddress);
        }
        Ok(candidate)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base58_encode(&self.as_bytes()))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self}, {})", self.network_prefix_char())
    }
}

impl Address {
    fn network_prefix_char(&self) -> char {
        self.network.prefix() as char
    }
}

impl FromStr for Address {
    type Err = DecodeError;

    /// Parses and fully validates an address string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = base58_decode(s).map_err(|_| DecodeError::InvalidAddress)?;
        Self::from_bytes(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    fn address_from_seed(seed: &[u8; 32], network: Network) -> Address {
        Address::new(
            network,
            KeyPair::spend(seed).public(),
            KeyPair::view(seed).public(),
        )
    }

    #[test]
    fn address_length_is_95_characters() {
        // 69 bytes = 8 full blocks (88 chars) + a 5-byte tail (7 chars).
        let addr = address_from_seed(&[1u8; 32], Network::Mainnet);
        assert_eq!(addr.to_string().len(), 95);
    }

    #[test]
    fn roundtrip_all_networks() {
        for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
            let addr = address_from_seed(&[7u8; 32], network);
            let s = addr.to_string();
            let back: Address = s.parse().expect("valid address");
            assert_eq!(back, addr);
            assert_eq!(back.network(), network);
        }
    }

    #[test]
    fn raw_bytes_roundtrip() {
        let addr = address_from_seed(&[9u8; 32], Network::Devnet);
        let bytes = addr.as_bytes();
        assert_eq!(Address::from_bytes(&bytes), Ok(addr));
    }

    #[test]
    fn checksum_breaks_on_single_flip() {
        let addr = address_from_seed(&[3u8; 32], Network::Mainnet);
        let mut bytes = addr.as_bytes();
        bytes[40] ^= 0x01;
        assert_eq!(
            Address::from_bytes(&bytes),
            Err(DecodeError::InvalidAddress)
        );
    }

    #[test]
    fn string_typo_rejected() {
        let addr = address_from_seed(&[3u8; 32], Network::Mainnet);
        let mut s: Vec<char> = addr.to_string().chars().collect();
        let mid = s.len() / 2;
        s[mid] = if s[mid] == '2' { '3' } else { '2' };
        let tampered: String = s.into_iter().collect();
        let result: Result<Address, _> = tampered.parse();
        assert_eq!(result, Err(DecodeError::InvalidAddress));
    }

    #[test]
    fn unknown_network_prefix_rejected() {
        let addr = address_from_seed(&[3u8; 32], Network::Mainnet);
        let mut bytes = addr.as_bytes();
        bytes[0] = b'X';
        // 'X' is not a network byte: rejected before the checksum.
        assert_eq!(
            Address::from_bytes(&bytes),
            Err(DecodeError::InvalidAddress)
        );
    }

    #[test]
    fn wrong_length_rejected() {
        assert_eq!(
            Address::from_bytes(&[0u8; 68]),
            Err(DecodeError::InvalidAddress)
        );
        assert_eq!(
            Address::from_bytes(&[0u8; 70]),
            Err(DecodeError::InvalidAddress)
        );
    }

    #[test]
    fn distinct_seeds_distinct_addresses() {
        let a = address_from_seed(&[1u8; 32], Network::Mainnet);
        let b = address_from_seed(&[2u8; 32], Network::Mainnet);
        assert_ne!(a, b);
        assert_ne!(a.to_string(), b.to_string());
    }
}
