//! Cross-implementation vector tests (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_vectors.py`, an independent implementation
//! of every routine below (pycryptodome for Keccak-256 and
//! Ed25519, a from-spec reimplementation of varints, block base58
//! and the address format). The Rust implementation must agree
//! bit for bit. A disagreement here is not a test failure: it is
//! a consensus fault, and it blocks the phase.

use antumbra_primitives::address::Address;
use antumbra_primitives::base58::{base58_decode, base58_encode};
use antumbra_primitives::hash::keccak256;
use antumbra_primitives::keys::{verify, KeyPair, Signature};
use antumbra_primitives::varint::{read_varint, write_varint};
use antumbra_primitives::Network;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    keccak256: Vec<KeccakVector>,
    varint: Vec<VarintVector>,
    base58: Vec<Base58Vector>,
    address: Vec<AddressVector>,
    signature: Vec<SignatureVector>,
}

#[derive(Deserialize)]
struct KeccakVector {
    hex: String,
    digest: String,
}

#[derive(Deserialize)]
struct VarintVector {
    value: u64,
    hex: String,
}

#[derive(Deserialize)]
struct Base58Vector {
    hex: String,
    text: String,
}

#[derive(Deserialize)]
struct AddressVector {
    seed: String,
    network: String,
    address: String,
}

#[derive(Deserialize)]
struct SignatureVector {
    seed: String,
    message_hex: String,
    signature_hex: String,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length in vectors");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex digit"))
        .collect()
}

fn load() -> Vectors {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("valid archived vector set")
}

fn network_by_name(name: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "devnet" => Network::Devnet,
        other => panic!("unknown network in vectors: {other}"),
    }
}

#[test]
fn keccak256_matches_the_independent_implementation() {
    for v in load().keccak256 {
        let data = unhex(&v.hex);
        assert_eq!(
            keccak256(&data).to_string(),
            v.digest,
            "keccak diverged on {}",
            v.hex
        );
    }
}

#[test]
fn varints_match_the_independent_implementation() {
    for v in load().varint {
        let mut buf = Vec::new();
        write_varint(v.value, &mut buf);
        assert_eq!(hex(&buf), v.hex, "varint encode diverged on {}", v.value);
        let bytes = unhex(&v.hex);
        let (decoded, used) = read_varint(&bytes).expect("archived varint decodes");
        assert_eq!(decoded, v.value);
        assert_eq!(used, bytes.len());
    }
}

#[test]
fn base58_matches_the_independent_implementation() {
    for v in load().base58 {
        let data = unhex(&v.hex);
        assert_eq!(
            base58_encode(&data),
            v.text,
            "base58 encode diverged on {}",
            v.hex
        );
        let decoded = base58_decode(&v.text).expect("archived base58 decodes");
        assert_eq!(hex(&decoded), v.hex, "base58 decode diverged on {}", v.text);
    }
}

#[test]
fn addresses_match_the_independent_implementation() {
    for v in load().address {
        let seed: [u8; 32] = unhex(&v.seed).try_into().expect("address seed is 32 bytes");
        let spend = KeyPair::spend(&seed);
        let view = KeyPair::view(&seed);
        let address = Address::new(network_by_name(&v.network), spend.public(), view.public());
        let rendered = address.to_string();
        assert_eq!(rendered, v.address, "address diverged for seed {}", v.seed);
        let parsed: Address = v.address.parse().expect("archived address parses");
        assert_eq!(parsed, address);
    }
}

#[test]
fn signatures_match_the_independent_implementation() {
    for v in load().signature {
        let seed: [u8; 32] = unhex(&v.seed)
            .try_into()
            .expect("signature seed is 32 bytes");
        let message = unhex(&v.message_hex);
        let expected = unhex(&v.signature_hex);
        let keypair = KeyPair::from_seed(&seed);
        let signature = keypair.sign(&message);
        assert_eq!(
            &signature.0[..],
            &expected[..],
            "signature diverged for seed {}",
            v.seed
        );
        assert!(verify(
            &Signature(expected.try_into().expect("64 byte signature")),
            &message,
            &keypair.public()
        ));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
