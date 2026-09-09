//! The minimum invariant battery of the P0 node (ADR-025).
//!
//! After every block the node checks: conservation, slot
//! alignment, emission accounting, tip shape, mempool hygiene.
//! Periodically and at the end it also checks the treasury
//! balance and the wallet truth against the ledger snapshot. The
//! emission and treasury accounting recompute the calendar
//! independently — the node does not trust the counters it just
//! wrote. A failure is a breach: the day stops and exits red.

use antumbra_state::coinbase::devnet_treasury_address;

use crate::engine::Engine;

/// The per-block verdict of the battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// `created = spent + emitted` holds on the ledger.
    pub conservation: bool,
    /// The applied slots equal the best tip's view, and the
    /// frontier is the best tip.
    pub slot_alignment: bool,
    /// The emitted total equals the independent calendar sum.
    pub emission_accounting: bool,
    /// The solo shape: exactly one tip (when strict).
    pub tip_shape: bool,
    /// No admitted transaction claims a spent output.
    pub mempool_hygiene: bool,
}

impl Report {
    /// Whether every invariant of the report held.
    #[must_use]
    pub const fn held(&self) -> bool {
        self.conservation
            && self.slot_alignment
            && self.emission_accounting
            && self.tip_shape
            && self.mempool_hygiene
    }
}

/// The per-block battery. Returns the report and the names of the
/// failed invariants, in order.
#[must_use]
pub fn check(engine: &Engine, strict_single_tip: bool) -> (Report, Vec<&'static str>) {
    let mut failures = Vec::new();
    let store = engine.store();
    let ledger = engine.ledger();
    let best = store.best_tip();

    let conservation = ledger.check_conservation().is_ok();
    if !conservation {
        failures.push("conservation: created != spent + emitted");
    }

    let slot_alignment = ledger.applied() == store.order_len(&best).unwrap_or(0)
        && engine.frontier() == best
        && store.order().len() as u64 == ledger.applied();
    if !slot_alignment {
        failures.push("slot alignment: the applied slots diverge from the best order");
    }

    let emission_accounting = ledger.emitted() == engine.checks().expected_emitted;
    if !emission_accounting {
        failures.push("emission accounting: the emitted total diverges from the calendar");
    }

    let tip_shape = !strict_single_tip || store.tips().len() == 1;
    if !tip_shape {
        failures.push("tip shape: the solo network holds more than one tip");
    }

    let mut mempool_hygiene = true;
    for reference in engine.mempool().claimed() {
        if ledger.is_spent(&reference) {
            mempool_hygiene = false;
            break;
        }
    }
    if !mempool_hygiene {
        failures.push("mempool hygiene: an admitted transaction claims a spent output");
    }

    (
        Report {
            conservation,
            slot_alignment,
            emission_accounting,
            tip_shape,
            mempool_hygiene,
        },
        failures,
    )
}

/// The periodic battery: the treasury balance and the wallet
/// truth, both recomputed from the ledger snapshot. Returns the
/// names of the failed checks.
#[must_use]
pub fn periodic(engine: &Engine) -> Vec<&'static str> {
    let mut failures = Vec::new();
    let ledger = engine.ledger();
    let snapshot = ledger.snapshot();

    let treasury = devnet_treasury_address();
    let mut treasury_balance = 0u64;
    for (_, entry) in &snapshot {
        if entry.address() == treasury {
            treasury_balance = treasury_balance.saturating_add(entry.amount().atomic());
        }
    }
    if treasury_balance != engine.checks().expected_treasury {
        failures.push("treasury accounting: the balance diverges from the calendar sum");
    }

    let wallets = [
        ("miner", &engine.wallets.miner),
        ("alice", &engine.wallets.alice),
        ("bob", &engine.wallets.bob),
    ];
    for (name, tracked) in wallets {
        let address = tracked.wallet.address();
        let mut truth = std::collections::BTreeSet::new();
        let mut truth_balance = 0u64;
        for (reference, entry) in &snapshot {
            if entry.address() == address {
                truth.insert(*reference);
                truth_balance = truth_balance.saturating_add(entry.amount().atomic());
            }
        }
        let tracked_set = tracked.tracker.unspent();
        if tracked_set != truth {
            failures.push("wallet truth: the tracker of a wallet diverges from the ledger");
            let _ = name;
        } else if tracked.tracker.unspent_atomic() != truth_balance {
            failures.push("wallet truth: the balance of a wallet diverges from the ledger");
            let _ = name;
        }
    }
    failures
}
