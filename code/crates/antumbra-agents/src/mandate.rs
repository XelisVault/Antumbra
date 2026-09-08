//! The Mandate: the declarative envelope of rights (ADR-021).

use crate::error::AgentError;
use antumbra_primitives::Hash;

/// How many destinations a Mandate may list.
pub const MANDATE_MAX_DESTS: usize = 8;

/// The amount ceiling of one Mandate, in atomic units: 100 ATU.
/// Above it a Mandate is malformed at construction: a human who
/// wants to give more opens a second Mandate and shows up in the
/// risk surface twice, visibly.
pub const MANDATE_MAX_AMOUNT_ATOMIC: u64 = 10_000_000_000;

/// The rails a Mandate may name: A and B only, by bits. The
/// constitutional rails (C, D) are not reachable from a Mandate:
/// a machine identity cannot vote a consensus change, and the
/// absence of the bits is the rule.
pub const MANDATE_RAILS_ALLOWED: u8 = 0b0000_0011;

/// The grammar version of this Mandate: zero, forever frozen
/// unless a rail C proposal rewrites it.
pub const MANDATE_VERSION: u8 = 0;

/// One Mandate: what an agent may do with the value it holds.
///
/// The grammar is deliberately tiny: no loops, no expressions,
/// no oracle calls, no network from inside a spend script. A
/// Mandate is data, not code: the interpreter of a future
/// version may grow (a rail C change with a full proposal), but
/// version zero cannot express "anything".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mandate {
    /// The grammar version, must be [`MANDATE_VERSION`].
    pub version: u8,
    /// The total value the Warrant may ever move, atomic units.
    pub max_amount: u64,
    /// The per-tick bound on one logical spend (one warrant
    /// check, possibly a whole batch), atomic units.
    pub max_rate: u64,
    /// The tick at which the Mandate dies: spends at or after it
    /// are rejected.
    pub expiry_tick: u32,
    /// The job types the agent may take (bitmask, the JobBoard
    /// vocabulary): jobs outside the mask are not the Warrant's
    /// business.
    pub job_types: u16,
    /// The rails the agent may propose into (bitmask, subset of
    /// A and B).
    pub rails: u8,
    /// The explicit destination set: the first `dest_count`
    /// entries are live, the rest must be the zero hash.
    pub dests: [Hash; MANDATE_MAX_DESTS],
    /// How many destinations are live.
    pub dest_count: u8,
}

impl Mandate {
    /// Builds a Mandate, grammar checked.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::MalformedMandate`] for every bound
    /// the grammar freezes: the version, the amount ceiling, the
    /// rate above the amount, the rails outside A and B, a
    /// destination count above the set size, a zero or repeated
    /// destination, or a padding slot that is not the zero hash.
    pub fn new(
        max_amount: u64,
        max_rate: u64,
        expiry_tick: u32,
        job_types: u16,
        rails: u8,
        dests: [Hash; MANDATE_MAX_DESTS],
        dest_count: u8,
    ) -> Result<Self, AgentError> {
        let mandate = Self {
            version: MANDATE_VERSION,
            max_amount,
            max_rate,
            expiry_tick,
            job_types,
            rails,
            dests,
            dest_count,
        };
        mandate.validate()?;
        Ok(mandate)
    }

    /// Checks every rule of the grammar.
    ///
    /// # Errors
    ///
    /// Same rejections as [`Mandate::new`].
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.version != MANDATE_VERSION {
            return Err(AgentError::MalformedMandate {
                field: "version",
                value: u64::from(self.version),
            });
        }
        if self.max_amount > MANDATE_MAX_AMOUNT_ATOMIC {
            return Err(AgentError::MalformedMandate {
                field: "max_amount",
                value: self.max_amount,
            });
        }
        if self.max_rate > self.max_amount {
            return Err(AgentError::MalformedMandate {
                field: "max_rate",
                value: self.max_rate,
            });
        }
        if self.rails & !MANDATE_RAILS_ALLOWED != 0 {
            return Err(AgentError::MalformedMandate {
                field: "rails",
                value: u64::from(self.rails),
            });
        }
        let count = usize::from(self.dest_count);
        if count > MANDATE_MAX_DESTS {
            return Err(AgentError::MalformedMandate {
                field: "dest_count",
                value: count as u64,
            });
        }
        for (index, dest) in self.dests.iter().enumerate() {
            let live = index < count;
            if live {
                if *dest == Hash::ZERO {
                    // The zero hash is the empty marker, not a
                    // destination: a live slot never holds it.
                    return Err(AgentError::MalformedMandate {
                        field: "dest",
                        value: u64::from(self.dest_count),
                    });
                }
            } else if *dest != Hash::ZERO {
                // Padding slots are exactly the zero hash.
                return Err(AgentError::MalformedMandate {
                    field: "dest_padding",
                    value: index as u64,
                });
            }
        }
        for i in 0..count {
            for j in (i + 1)..count {
                if self.dests[i] == self.dests[j] {
                    return Err(AgentError::DuplicateDest);
                }
            }
        }
        Ok(())
    }

    /// Whether `dest` is inside the perimeter. An empty set
    /// permits nothing: there is no wildcard, ever.
    #[must_use]
    pub fn permits_dest(&self, dest: &Hash) -> bool {
        // The count clamps like the independent implementation
        // slices: a malformed count above the set size reads as
        // the whole set, never as a panic.
        let count = (self.dest_count as usize).min(MANDATE_MAX_DESTS);
        self.dests[..count].contains(dest)
    }

    /// Whether the Mandate allows job type `job` (bit set).
    #[must_use]
    pub const fn permits_job(&self, job: u16) -> bool {
        self.job_types & job != 0
    }

    /// The canonical byte encoding: version, amounts, expiry,
    /// masks, the count, the fixed destination set. Fixed width,
    /// no varint, no ambiguity.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; MANDATE_BYTES] {
        let mut out = [0u8; MANDATE_BYTES];
        out[0] = self.version;
        out[1..9].copy_from_slice(&self.max_amount.to_be_bytes());
        out[9..17].copy_from_slice(&self.max_rate.to_be_bytes());
        out[17..21].copy_from_slice(&self.expiry_tick.to_be_bytes());
        out[21..23].copy_from_slice(&self.job_types.to_be_bytes());
        out[23] = self.rails;
        out[24] = self.dest_count;
        for (i, dest) in self.dests.iter().enumerate() {
            out[25 + i * 32..25 + (i + 1) * 32].copy_from_slice(&dest.0);
        }
        out
    }
}

/// The fixed width of the canonical Mandate encoding.
pub const MANDATE_BYTES: usize = 25 + 32 * MANDATE_MAX_DESTS;
