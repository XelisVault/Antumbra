//! The honest devnet status (ADR-025, ADR-023).
//!
//! A fixed set of fields, canonically encoded and hashed: the
//! **status id**. Two runs of the same day print the same id —
//! the determinism gate. The rendered text adds the devnet time
//! and the wall time, which the id excludes, and the honest
//! language: this is a development scaffold, the numbers are the
//! numbers, and the claim of a run is its invariant list.

use std::time::Duration;

use antumbra_primitives::{keccak256, Hash, Writer};

use crate::devnet::BLOCK_INTERVAL_MS;
use crate::engine::Engine;

/// The status of a node at a moment: the numbers and the
/// verdicts, nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The slots applied, the genesis included.
    pub blocks: u64,
    /// The height of the best tip.
    pub height: u64,
    /// The number of mining tips.
    pub tips: usize,
    /// The length of the consensus order of the best tip.
    pub order_len: u64,
    /// The best tip id.
    pub best_tip: Hash,
    /// Total value ever created, coinbases included (atomic).
    pub created: u64,
    /// Total value ever consumed by inputs (atomic).
    pub spent: u64,
    /// Total emission: the rewards, not the recycled fees
    /// (atomic).
    pub emitted: u64,
    /// The unspent balance of the treasury address (atomic).
    pub treasury: u64,
    /// The number of unspent outputs.
    pub utxos: usize,
    /// Transfer transactions applied.
    pub transfers: u64,
    /// Coinbase transactions applied.
    pub coinbases: u64,
    /// Ledger rebuilds after reorganizations.
    pub rebuilds: u64,
    /// Whether every invariant of the last battery held.
    pub invariants_held: bool,
}

impl Status {
    /// The status of an engine: the ledger counters, the store
    /// shape, the trackers' verdicts. The wall time is read for
    /// the report and never enters the id.
    #[must_use]
    pub fn of(engine: &Engine, wall: Duration) -> Reported {
        let store = engine.store();
        let ledger = engine.ledger();
        let best = store.best_tip();
        let treasury_address = antumbra_state::coinbase::devnet_treasury_address();
        let mut treasury = 0u64;
        let snapshot = ledger.snapshot();
        for (_, entry) in &snapshot {
            if entry.address() == treasury_address {
                treasury = treasury.saturating_add(entry.amount().atomic());
            }
        }
        let (_, failures) = crate::invariants::check(engine, false);
        let status = Self {
            blocks: ledger.applied(),
            height: store.height(&best).unwrap_or(0),
            tips: store.tips().len(),
            order_len: store.order().len() as u64,
            best_tip: best,
            created: ledger.created(),
            spent: ledger.spent_value(),
            emitted: ledger.emitted(),
            treasury,
            utxos: ledger.len(),
            transfers: engine.stats().transfers,
            coinbases: engine.stats().coinbases,
            rebuilds: engine.stats().rebuilds,
            invariants_held: failures.is_empty(),
        };
        Reported {
            status,
            wall_ms: wall.as_millis() as u64,
        }
    }

    /// The status id: the Keccak-256 of the canonical encoding of
    /// the fields. Deterministic: the same day, the same id.
    #[must_use]
    pub fn id(&self) -> Hash {
        let mut writer = Writer::new();
        writer.write_u64(self.blocks);
        writer.write_u64(self.height);
        writer.write_u64(self.tips as u64);
        writer.write_u64(self.order_len);
        writer.write_array(self.best_tip.as_bytes());
        writer.write_u64(self.created);
        writer.write_u64(self.spent);
        writer.write_u64(self.emitted);
        writer.write_u64(self.treasury);
        writer.write_u64(self.utxos as u64);
        writer.write_u64(self.transfers);
        writer.write_u64(self.coinbases);
        writer.write_u64(self.rebuilds);
        writer.write_bool(self.invariants_held);
        keccak256(&writer.finish())
    }
}

/// A status with its wall clock reading: the report the operator
/// reads. The wall time never enters the id.
pub struct Reported {
    /// The status itself.
    pub status: Status,
    /// The wall clock of the run, in milliseconds.
    pub wall_ms: u64,
}

/// Renders an amount in whole ATU with the eight decimals of
/// ADR-008.
fn atu(atomic: u64) -> String {
    format!("{}.{:08}", atomic / 100_000_000, atomic % 100_000_000)
}

/// Renders a duration in days, hours, minutes and seconds.
fn duration_text(ms: u64) -> String {
    let total_seconds = ms / 1_000;
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
}

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

impl core::fmt::Display for Reported {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let status = &self.status;
        let devnet_ms = status.blocks.saturating_sub(1) * BLOCK_INTERVAL_MS;
        let verdict = if status.invariants_held {
            "held"
        } else {
            "BREACHED"
        };
        writeln!(f, "ANTUMBRA development network - node status (ADR-025)")?;
        writeln!(f, "  blocks applied      {}", status.blocks)?;
        writeln!(f, "  height              {}", status.height)?;
        writeln!(f, "  tips                {}", status.tips)?;
        writeln!(f, "  best tip            {}", hex(&status.best_tip))?;
        writeln!(f, "  consensus order     {} slots", status.order_len)?;
        writeln!(f, "  devnet time         {}", duration_text(devnet_ms))?;
        writeln!(f, "  wall time           {}", duration_text(self.wall_ms))?;
        writeln!(f, "  emission            {} ATU", atu(status.emitted))?;
        writeln!(
            f,
            "  created / spent     {} / {} ATU",
            atu(status.created),
            atu(status.spent)
        )?;
        writeln!(f, "  treasury            {} ATU", atu(status.treasury))?;
        writeln!(f, "  unspent outputs     {}", status.utxos)?;
        writeln!(
            f,
            "  transactions        {} coinbases, {} transfers",
            status.coinbases, status.transfers
        )?;
        writeln!(f, "  reorg rebuilds      {}", status.rebuilds)?;
        writeln!(f, "  invariants          {verdict}")?;
        writeln!(f, "  status id           {}", hex(&status.id()))?;
        write!(
            f,
            "This is a development scaffold: Keccak work function, transparent\n\
             version 1 transactions, solo driver, no network. RandomX and the\n\
             privacy layer arrive later. The claim of this run is the invariant\n\
             list, nothing more."
        )
    }
}
