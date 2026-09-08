//! The Warrant: the bounded continuation that spends.

use crate::error::AgentError;
use crate::mandate::Mandate;
use antumbra_primitives::{keccak256, Hash};

/// The delay, in ticks, between a revocation and the drain of
/// the remaining bond to the sponsor: two days at ten-minute
/// ticks. The delay is long enough for the agent to finish a
/// settlement in flight, short enough that a captured agent
/// cannot park value forever.
pub const DRAIN_DELAY_TICKS: u32 = 288;

/// One Warrant: the spend authority of one agent under one
/// Mandate.
///
/// The state is monotone: the nonce only moves forward by
/// exactly one per logical spend (a replay and a gap are both
/// refused), the remaining only moves down, and the revocation
/// only moves in. A revoked Warrant is fail-closed everywhere:
/// spends, streams and unsold receipts all read the same wall.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Warrant {
    mandate: Mandate,
    remaining: u64,
    nonce: u32,
    revoked: bool,
    revocation_tick: u32,
}

impl Warrant {
    /// Opens a Warrant at full capacity under a validated
    /// Mandate.
    ///
    /// # Errors
    ///
    /// Returns the Mandate rejections of [`Mandate::new`].
    pub fn new(mandate: Mandate) -> Result<Self, AgentError> {
        mandate.validate()?;
        Ok(Self {
            remaining: mandate.max_amount,
            nonce: 0,
            revoked: false,
            revocation_tick: 0,
            mandate,
        })
    }

    /// The Mandate this Warrant spends under.
    #[must_use]
    pub const fn mandate(&self) -> &Mandate {
        &self.mandate
    }

    /// The root of the Warrant: what the uniform authority
    /// encoding commits to on-chain.
    #[must_use]
    pub fn root(&self) -> Hash {
        keccak256(&self.mandate.canonical_bytes())
    }

    /// One logical spend: amount, destination, the successor
    /// nonce, the tick.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Revoked`] after revocation (the
    /// fail-closed wall), [`AgentError::Expired`] at or after
    /// the expiry tick, [`AgentError::NonceNotMonotone`] for a
    /// replay or a gap, and the bounds rejections of the
    /// Mandate for the amount and the perimeter.
    pub fn spend(
        &mut self,
        dest: &Hash,
        amount: u64,
        nonce: u32,
        tick: u32,
    ) -> Result<u64, AgentError> {
        if self.revoked {
            return Err(AgentError::Revoked);
        }
        if tick >= self.mandate.expiry_tick {
            return Err(AgentError::Expired {
                tick,
                expiry: self.mandate.expiry_tick,
            });
        }
        if amount == 0 {
            return Err(AgentError::ZeroAmount);
        }
        if nonce != self.nonce.wrapping_add(1) {
            return Err(AgentError::NonceNotMonotone {
                given: nonce,
                expected: self.nonce.wrapping_add(1),
            });
        }
        if !self.mandate.permits_dest(dest) {
            return Err(AgentError::PerimeterDest);
        }
        if amount > self.mandate.max_rate {
            return Err(AgentError::OverRate {
                amount,
                max_rate: self.mandate.max_rate,
            });
        }
        if amount > self.remaining {
            return Err(AgentError::OverCap {
                amount,
                remaining: self.remaining,
            });
        }
        self.remaining -= amount;
        self.nonce = nonce;
        Ok(amount)
    }

    /// Revokes: the fail-closed wall goes up. A second
    /// revocation keeps the first tick (the earliest wins, a
    /// re-release is not a thing).
    pub fn revoke(&mut self, tick: u32) {
        if !self.revoked {
            self.revoked = true;
            self.revocation_tick = tick;
        }
    }

    /// Whether the remaining bond may drain to the sponsor:
    /// revoked, and the drain delay has passed. The sponsor
    /// collects, never the attacker who took the key.
    #[must_use]
    pub const fn drain_ready(&self, tick: u32) -> bool {
        self.revoked && tick >= self.revocation_tick.saturating_add(DRAIN_DELAY_TICKS)
    }

    /// The state, as the vector set archives it after every
    /// operation: remaining, nonce, revoked.
    #[must_use]
    pub const fn state(&self) -> (u64, u32, bool) {
        (self.remaining, self.nonce, self.revoked)
    }
}
