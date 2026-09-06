//! Cross-implementation vector tests for the ordering layer
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_dag_vectors.py`, an independent
//! implementation of the header and block codecs, the payload
//! root, the work function, the insertion battery, the coloring
//! and the consensus order (pycryptodome for Keccak-256,
//! from-spec reimplementations for everything else). The Rust
//! implementation must agree bit for bit, on every vector set:
//! the encodings and ids, the mined nonces, the blue scores and
//! blue sets, the selected parents, the consensus orders, and
//! every rejection. A disagreement here is not a test failure: it
//! is a consensus fault, and it blocks the phase.

use antumbra_dag::block::payload_root;
use antumbra_dag::dag::{Policy, GENESIS_TIMESTAMP_MS};
use antumbra_dag::{leading_zero_bits, mine, Block, Dag, DagError, Header};
use antumbra_primitives::Hash;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    genesis: GenesisVector,
    header: Vec<HeaderVector>,
    block: Vec<BlockVector>,
    pow: Vec<PowVector>,
    dag: Vec<DagVector>,
    invalid: Vec<InvalidVector>,
    insert_reject: Vec<RejectVector>,
}

#[derive(Deserialize)]
struct GenesisVector {
    timestamp: u64,
    payload_root: String,
    canonical_hex: String,
    id: String,
}

#[derive(Deserialize)]
struct HeaderVector {
    parents: Vec<String>,
    height: u64,
    timestamp: u64,
    nonce: u64,
    payload_root: String,
    canonical_hex: String,
    id: String,
}

#[derive(Deserialize)]
struct BlockVector {
    parents: Vec<String>,
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_ids: Vec<String>,
    canonical_hex: String,
    id: String,
}

#[derive(Deserialize)]
struct PowVector {
    parents: Vec<String>,
    height: u64,
    timestamp: u64,
    payload_root: String,
    bits: u32,
    nonce: u64,
    id: String,
    leading_bits: u32,
}

#[derive(Deserialize)]
struct DagVector {
    nodes: Vec<NodeVector>,
    tip: usize,
    order: Vec<usize>,
}

#[derive(Deserialize)]
struct NodeVector {
    parents: Vec<usize>,
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_ids: Vec<String>,
    id: String,
    blue_score: u64,
    selected_parent: Option<usize>,
    blue_set: Vec<usize>,
}

#[derive(Deserialize)]
struct InvalidVector {
    hex: String,
    error: String,
}

#[derive(Deserialize)]
struct RejectVector {
    parents: Vec<String>,
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_ids: Vec<String>,
    difficulty_bits: u32,
    max_future_ms: u64,
    now_ms: u64,
    error: String,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length in vectors");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex digit"))
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn unhex_hashes(items: &[String]) -> Vec<Hash> {
    items.iter().map(|s| Hash(unhex32(s))).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load() -> Vectors {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("valid archived vector set")
}

fn rebuild_header(
    parents: &[String],
    height: u64,
    timestamp: u64,
    nonce: u64,
    root: &str,
) -> Header {
    Header::new(
        unhex_hashes(parents),
        height,
        timestamp,
        nonce,
        Hash(unhex32(root)),
    )
}

fn rebuild_block(v: &BlockVector) -> Block {
    let tx_ids = unhex_hashes(&v.tx_ids);
    let root = payload_root(&tx_ids);
    let header = Header::new(
        unhex_hashes(&v.parents),
        v.height,
        v.timestamp,
        v.nonce,
        root,
    );
    Block::new(header, tx_ids)
}

fn expect_reject(name: &str, error: &DagError) {
    let matches = match name {
        "InvalidVersion" => matches!(error, DagError::InvalidVersion(_)),
        "NoParents" => matches!(error, DagError::NoParents),
        "TooManyParents" => matches!(error, DagError::TooManyParents(_)),
        "UnsortedParents" => matches!(error, DagError::UnsortedParents),
        "TooManyTransactions" => matches!(error, DagError::TooManyTransactions(_)),
        "UnsortedTransactions" => matches!(error, DagError::UnsortedTransactions),
        "PayloadRootMismatch" => matches!(error, DagError::PayloadRootMismatch { .. }),
        "ZeroParent" => matches!(error, DagError::ZeroParent),
        "UnknownParent" => matches!(error, DagError::UnknownParent(_)),
        "Duplicate" => matches!(error, DagError::Duplicate(_)),
        "HeightMismatch" => matches!(error, DagError::HeightMismatch { .. }),
        "TimestampBehind" => matches!(error, DagError::TimestampBehind { .. }),
        "TimestampFuture" => matches!(error, DagError::TimestampFuture { .. }),
        "InsufficientWork" => matches!(error, DagError::InsufficientWork { .. }),
        "Decode" => matches!(error, DagError::Decode(_)),
        other => panic!("unknown rejection name in vectors: {other}"),
    };
    assert!(matches, "expected {name}, got {error}");
}

#[test]
fn the_genesis_block_is_the_archived_one() {
    let vectors = load();
    let genesis = Block::devnet_genesis();
    assert_eq!(genesis.header().timestamp(), vectors.genesis.timestamp);
    assert_eq!(
        hex(genesis.header().payload_root().as_bytes()),
        vectors.genesis.payload_root
    );
    assert_eq!(hex(&genesis.encode()), vectors.genesis.canonical_hex);
    assert_eq!(genesis.id().to_string(), vectors.genesis.id);
    assert_eq!(genesis.header().timestamp(), GENESIS_TIMESTAMP_MS);
}

#[test]
fn headers_match_the_independent_implementation() {
    for v in load().header {
        let header = rebuild_header(&v.parents, v.height, v.timestamp, v.nonce, &v.payload_root);
        // Canonical encoding, bit for bit.
        assert_eq!(
            hex(&header.encode()),
            v.canonical_hex,
            "canonical encoding diverged (height {})",
            v.height
        );
        // The id is Keccak-256 of the encoding.
        assert_eq!(header.id().to_string(), v.id);
        // Strict decoding of the archived bytes rebuilds the exact
        // header.
        let decoded = Header::decode(&unhex(&v.canonical_hex))
            .unwrap_or_else(|e| panic!("archived header decodes: {e}"));
        assert_eq!(decoded, header);
        assert_eq!(hex(&decoded.encode()), v.canonical_hex);
    }
}

#[test]
fn blocks_match_the_independent_implementation() {
    for v in load().block {
        let block = rebuild_block(&v);
        assert_eq!(hex(&block.encode()), v.canonical_hex);
        assert_eq!(block.id().to_string(), v.id);
        // The header root commits the payload, and the strict
        // decode of the archived bytes rebuilds the block.
        assert_eq!(block.header().payload_root(), payload_root(block.tx_ids()));
        let decoded = Block::decode(&unhex(&v.canonical_hex))
            .unwrap_or_else(|e| panic!("archived block decodes: {e}"));
        assert_eq!(decoded, block);
        assert_eq!(hex(&decoded.encode()), v.canonical_hex);
    }
}

#[test]
fn work_matches_the_independent_implementation() {
    for v in load().pow {
        // The archived nonce yields the archived id with at least
        // the archived difficulty.
        let header = rebuild_header(&v.parents, v.height, v.timestamp, v.nonce, &v.payload_root);
        assert_eq!(header.id().to_string(), v.id);
        assert_eq!(leading_zero_bits(&header.id()), v.leading_bits);
        assert!(leading_zero_bits(&header.id()) >= v.bits);
        // The mining walk, replayed from nonce zero, finds the
        // same nonce: the walk is deterministic.
        let skeleton = rebuild_header(&v.parents, v.height, v.timestamp, 0, &v.payload_root);
        let mined = mine(&skeleton, v.bits, 1 << 24)
            .unwrap_or_else(|| panic!("the walk must find the archived nonce (bits {})", v.bits));
        assert_eq!(mined.nonce(), v.nonce);
        assert_eq!(mined.id().to_string(), v.id);
    }
}

#[test]
fn the_dag_matches_the_independent_implementation() {
    for v in load().dag {
        let genesis = Block::devnet_genesis();
        let mut dag = Dag::new(&genesis).expect("the genesis opens");
        assert_eq!(dag.len(), 1);

        // Node zero is the archived genesis.
        assert_eq!(dag.genesis().to_string(), v.nodes[0].id);

        let ids: Vec<Hash> = v.nodes.iter().map(|n| Hash(unhex32(&n.id))).collect();
        for (index, node) in v.nodes.iter().enumerate().skip(1) {
            let tx_ids = unhex_hashes(&node.tx_ids);
            let root = payload_root(&tx_ids);
            let parents: Vec<Hash> = node.parents.iter().map(|&p| ids[p]).collect();
            let header = Header::new(parents, node.height, node.timestamp, node.nonce, root);
            let block = Block::new(header, tx_ids);
            let id = dag
                .insert(&block, &Policy::VECTORS, u64::MAX)
                .unwrap_or_else(|e| panic!("node {index} inserts: {e}"));
            // The block id, the blue score and the selected parent
            // agree with the independent coloring.
            assert_eq!(id.to_string(), node.id, "node {index} id diverged");
            assert_eq!(
                dag.blue_score(&id),
                Some(node.blue_score),
                "node {index} blue score diverged"
            );
            let expected_sp = node
                .selected_parent
                .map(|p| ids[p])
                .expect("a non-genesis node has a selected parent");
            assert_eq!(
                dag.selected_parent(&id),
                Some(expected_sp),
                "node {index} selected parent diverged"
            );
        }

        // The blue set and the consensus order of the best tip.
        let tip = dag.best_tip().expect("a tip exists");
        assert_eq!(tip.to_string(), v.nodes[v.tip].id);
        let expected_blues: BTreeSet<Hash> =
            v.nodes[v.tip].blue_set.iter().map(|&p| ids[p]).collect();
        let blues = dag.blues(&tip).expect("held").clone();
        assert_eq!(blues, expected_blues, "the blue set of the tip diverged");
        let order = dag.consensus_order(&tip).expect("the order exists");
        let expected_order: Vec<Hash> = v.order.iter().map(|&p| ids[p]).collect();
        assert_eq!(order, expected_order, "the consensus order diverged");
    }
}

#[test]
fn the_dag_vector_sets_cover_the_boundaries() {
    let vectors = load();
    // A sixteen-parent header and a sixty-four-transaction block.
    assert!(vectors.header.iter().any(|v| v.parents.len() == 16));
    assert!(vectors.block.iter().any(|v| v.tx_ids.len() == 64));
    // The wide fork must turn blocks red: at least one node of
    // the second set has a parent outside its blue set, which is
    // exactly what a red parent is.
    let wide = &vectors.dag[1];
    assert!(wide
        .nodes
        .iter()
        .any(|n| { n.parents.iter().any(|p| !n.blue_set.contains(p)) }));
    // Every set ends its order on its own tip.
    for v in &vectors.dag {
        assert_eq!(*v.order.last().expect("non-empty"), v.tip);
    }
}

#[test]
fn the_invalid_bytes_are_rejected_with_the_archived_reason() {
    for v in load().invalid {
        let bytes = unhex(&v.hex);
        match Block::decode(&bytes) {
            Err(e) => expect_reject(&v.error, &e),
            Ok(block) => panic!(
                "the bytes must be rejected ({}) but decoded as {}",
                v.error,
                block.id()
            ),
        }
    }
}

#[test]
fn the_rejected_insertions_name_the_archived_rule() {
    let vectors = load();
    // The rejection battery replays against the first DAG set,
    // the textbook construction.
    let base = &vectors.dag[0];
    for v in &vectors.insert_reject {
        let genesis = Block::devnet_genesis();
        let mut dag = Dag::new(&genesis).expect("the genesis opens");
        let ids: Vec<Hash> = base.nodes.iter().map(|n| Hash(unhex32(&n.id))).collect();
        for (index, node) in base.nodes.iter().enumerate().skip(1) {
            let tx_ids = unhex_hashes(&node.tx_ids);
            let root = payload_root(&tx_ids);
            let parents: Vec<Hash> = node.parents.iter().map(|&p| ids[p]).collect();
            let header = Header::new(parents, node.height, node.timestamp, node.nonce, root);
            dag.insert(&Block::new(header, tx_ids), &Policy::VECTORS, u64::MAX)
                .unwrap_or_else(|e| panic!("the base node {index} inserts: {e}"));
        }
        // The offending block, under its own policy and clock.
        let tx_ids = unhex_hashes(&v.tx_ids);
        let root = payload_root(&tx_ids);
        let parents = unhex_hashes(&v.parents);
        let header = Header::new(parents, v.height, v.timestamp, v.nonce, root);
        let policy = Policy {
            difficulty_bits: v.difficulty_bits,
            max_future_ms: v.max_future_ms,
        };
        match dag.insert(&Block::new(header, tx_ids), &policy, v.now_ms) {
            Err(e) => expect_reject(&v.error, &e),
            Ok(id) => panic!(
                "the insertion must be rejected ({}) but inserted as {id}",
                v.error
            ),
        }
    }
}
