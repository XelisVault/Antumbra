//! The streams: rate, cap, fail-closed at revocation.

use antumbra_primitives::Hash;

/// One payment stream: `rate` per tick, until `cap` or the cut.
///
/// A stream pays under a Warrant. When the Warrant is revoked,
/// the next tick pays zero and every tick after it too: the cut
/// lands at the tick, not at the era. A slow revocation against
/// a fast stream is the attack C14 of the audit; the answer is
/// that the tick is the fail-closed granularity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stream {
    /// The beneficiary.
    pub to: Hash,
    /// The payment per tick, atomic units.
    pub rate_per_tick: u64,
    /// The total the stream may ever pay, atomic units.
    pub cap: u64,
}

/// The state of one stream under one Warrant.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StreamState {
    /// Total paid so far.
    pub paid: u64,
    /// Ticks elapsed.
    pub ticks: u32,
    /// Whether the stream was closed by its owner.
    pub closed: bool,
}

/// Runs one tick of the stream.
///
/// Returns what the tick paid: zero when the stream is closed,
/// when the Warrant is revoked (the fail-closed cut), or when
/// the cap is exhausted; otherwise the rate, or what remains of
/// the cap. The tick counter advances on every call: a closed
/// or revoked stream still ages, it just does not pay.
#[must_use]
pub fn tick(state: &mut StreamState, stream: &Stream, warrant_revoked: bool) -> u64 {
    state.ticks += 1;
    if state.closed || warrant_revoked {
        return 0;
    }
    let room = stream.cap.saturating_sub(state.paid);
    let pay = stream.rate_per_tick.min(room);
    state.paid += pay;
    pay
}

/// Closes the stream from the payer side: an explicit stop that
/// predates any revocation.
pub fn close(state: &mut StreamState) {
    state.closed = true;
}
