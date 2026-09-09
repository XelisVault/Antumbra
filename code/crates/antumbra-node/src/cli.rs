//! The command line of the node binary (ADR-025).
//!
//! Two commands, hand-parsed — a binary with no external
//! dependency is auditable in one read: `genesis` prints the
//! frozen devnet genesis id; `day` runs the P0 driver and exits
//! zero only if every invariant held on every block.

use crate::engine::{self, Breach};
use antumbra_dag::Block;
use antumbra_primitives::Hash;

/// The usage text.
const USAGE: &str = "antumbra-node: the development network node (ADR-025)

USAGE:
    antumbra-node genesis
        Print the devnet genesis id: the frozen constant of the
        ordering layer, archived in its cross vector set.

    antumbra-node day [--blocks N] [--difficulty B] [--spend-every K]
        Mine N blocks (default 43200, one devnet day) on the best
        tip, apply each to the ledger, check the invariant battery
        after every block, and print the honest status. Exits zero
        only if every invariant held and no breach was recorded.

    --blocks N        the number of blocks to mine (default 43200)
    --difficulty B    the Keccak leading zero bits (default 16)
    --spend-every K   the activity script interval (default 16)";

/// The hex of a hash, lowercase.
fn hex(hash: &Hash) -> String {
    let bytes = hash.as_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parses a `--flag value` pair from the arguments.
fn flag_value(args: &[String], name: &str) -> Result<Option<String>, String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == name {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{name} needs a value"))?;
            return Ok(Some(value.clone()));
        }
        index += 1;
    }
    Ok(None)
}

/// Parses a `--flag value` integer pair.
fn flag_integer(args: &[String], name: &str) -> Result<Option<u64>, String> {
    match flag_value(args, name)? {
        Some(text) => {
            Ok(Some(text.parse::<u64>().map_err(|_| {
                format!("{name} needs an integer, found {text}")
            })?))
        }
        None => Ok(None),
    }
}

/// Runs the command line. Returns the process exit code; the
/// error string is the usage.
///
/// # Errors
///
/// Returns the usage text on an unknown command or a malformed
/// flag.
pub fn run(args: &[String]) -> Result<i32, String> {
    match args.first().map(String::as_str) {
        Some("genesis") => {
            let genesis = Block::devnet_genesis();
            println!("devnet genesis id: {}", hex(&genesis.id()));
            println!("timestamp: {} ms", genesis.header().timestamp());
            println!("payload: empty, nonce: 0, height: 0");
            Ok(0)
        }
        Some("day") => run_day(args),
        _ => Err(USAGE.to_string()),
    }
}

/// The day driver behind the command line.
fn run_day(args: &[String]) -> Result<i32, String> {
    let blocks = flag_integer(args, "--blocks")?.unwrap_or(crate::devnet::DEFAULT_DAY_BLOCKS);
    let difficulty =
        flag_integer(args, "--difficulty")?.unwrap_or(u64::from(crate::devnet::DEFAULT_DIFFICULTY));
    let spend_every = flag_integer(args, "--spend-every")?.unwrap_or(crate::devnet::SPEND_EVERY);
    if blocks == 0 {
        return Err("--blocks must be at least one".to_string());
    }
    if difficulty > 64 {
        return Err("--difficulty is at most 64 bits".to_string());
    }
    let difficulty = u32::try_from(difficulty).expect("the bound above keeps it in range");
    println!(
        "antumbra-node day: {blocks} blocks, difficulty {difficulty}, spend every {spend_every}"
    );
    println!(
        "run parameters id: {}",
        hex(&engine::day_parameters(blocks, difficulty, spend_every))
    );
    let step = (blocks / 10).max(1);
    let mut progress = |block: u64| {
        if block % step == 0 || block == blocks {
            println!("  block {block}/{blocks}");
        }
    };
    match engine::run_day(blocks, difficulty, spend_every, &mut progress) {
        Ok(outcome) => {
            println!("{}", outcome.reported);
            Ok(0)
        }
        Err(breach) => {
            report_breach(&breach);
            Ok(1)
        }
    }
}

/// Prints a breach with the honest header.
fn report_breach(breach: &Breach) {
    println!("the day stopped on a breach:");
    println!("  {breach}");
    println!(
        "this is a fault of the scaffold or the driver, not a network event:\n\
         the development network is a solo miner and the script is honest."
    );
}
