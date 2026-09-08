//! The jobs and the inverse auction.

use crate::class::Class;
use crate::error::JobsError;
use antumbra_primitives::Hash;

/// The bounty ceiling of one job, atomic units: 1 000 ATU.
/// Above it, split the job: no single employer buys the whole
/// attention of a market at once.
pub const JOB_BOUNTY_MAX_ATOMIC: u64 = 100_000_000_000;

/// The bond ceiling of one job, atomic units: 250 ATU.
pub const JOB_BOND_MAX_ATOMIC: u64 = 25_000_000_000;

/// The maximum number of reviewers an acceptance can require.
pub const ACCEPTANCE_MAX_REVIEWERS: u8 = 5;

/// How the job assigns its work.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exclusivity {
    /// First valid artifact wins: the race that suits bugs.
    Open,
    /// Inverse auction among the qualified: the cheapest wins,
    /// ties break on past efficiency.
    Auction,
    /// The employer designates: the Integrator case.
    Assigned,
}

impl Exclusivity {
    /// The mode of a canonical label, or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "open" => Some(Self::Open),
            "auction" => Some(Self::Auction),
            "assigned" => Some(Self::Assigned),
            _ => None,
        }
    }

    /// The canonical label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Auction => "auction",
            Self::Assigned => "assigned",
        }
    }
}

/// What settles a submission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Acceptance {
    /// The acceptance tests decide: replayable, no taste.
    AutoTests,
    /// `n` reviewers must ack: hostile review is a job too.
    Reviewers {
        /// How many acks settle the submission, one to five.
        n: u8,
    },
    /// The employer signs: designated work.
    EmployerSign,
}

impl Acceptance {
    /// The canonical label of the acceptance mode.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AutoTests => "auto_tests",
            Self::Reviewers { .. } => "reviewers",
            Self::EmployerSign => "employer_sign",
        }
    }
}

/// One job of the board.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Job {
    /// The job id.
    pub job_id: u32,
    /// The class floor: below it, no bid, no submission.
    pub class_min: Class,
    /// The hash of the specification and its acceptance tests.
    pub spec_hash: Hash,
    /// The bounty, atomic units.
    pub bounty_atomic: u64,
    /// The bond a worker must lock to submit.
    pub bond_required_atomic: u64,
    /// The height at which the job stops accepting anything.
    pub deadline_height: u32,
    /// How the work is assigned.
    pub exclusivity: Exclusivity,
    /// What settles a submission.
    pub acceptance: Acceptance,
    /// Whether the specification is sealed (hash only, opened
    /// to bonded applicants).
    pub sealed: bool,
}

impl Job {
    /// Checks every rule of the job grammar.
    ///
    /// # Errors
    ///
    /// Returns [`JobsError::MalformedJob`] for every bound: a
    /// bounty above the ceiling, a bond above its ceiling, a
    /// past deadline, a reviewer count outside one to five.
    pub fn validate(&self) -> Result<(), JobsError> {
        if self.bounty_atomic > JOB_BOUNTY_MAX_ATOMIC {
            return Err(JobsError::MalformedJob {
                field: "bounty_atomic",
                value: self.bounty_atomic,
            });
        }
        if self.bond_required_atomic > JOB_BOND_MAX_ATOMIC {
            return Err(JobsError::MalformedJob {
                field: "bond_required_atomic",
                value: self.bond_required_atomic,
            });
        }
        if self.deadline_height == 0 {
            return Err(JobsError::MalformedJob {
                field: "deadline_height",
                value: 0,
            });
        }
        if let Acceptance::Reviewers { n } = self.acceptance {
            if n == 0 || n > ACCEPTANCE_MAX_REVIEWERS {
                return Err(JobsError::MalformedJob {
                    field: "reviewers",
                    value: u64::from(n),
                });
            }
        }
        Ok(())
    }

    /// Whether the job accepts work at `height`.
    #[must_use]
    pub const fn open_at(&self, height: u32) -> bool {
        height <= self.deadline_height
    }
}

/// One bid of an inverse auction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bid {
    /// The bidder identity (a Cipher, as the board knows it).
    pub bidder: u32,
    /// The offered price, atomic units: below or at the bounty.
    pub price_atomic: u64,
    /// The past efficiency of the bidder, per mille: the tie
    /// break the auction prefers, because an efficient worker
    /// leaves budget for the next job.
    pub efficiency_pm: u32,
    /// The class the bidder certifies.
    pub class: Class,
}

/// The winner of an inverse auction, or `None` when no bid
/// qualifies.
///
/// Order: the lowest price, then the highest past efficiency,
/// then the lower identity. Every step deterministic, the whole
/// replayable from the bid set alone. A bidder below the class
/// floor of the job is refused, not discounted.
///
/// # Errors
///
/// Returns [`JobsError::UnderQualified`] when a bid sits below
/// the class floor: the caller decides whether to reject the
/// auction or the bid.
pub fn auction_winner(bids: &[Bid], class_min: Class) -> Result<Option<Bid>, JobsError> {
    let mut best: Option<Bid> = None;
    for bid in bids {
        if bid.class < class_min {
            return Err(JobsError::UnderQualified {
                class_min: class_min as u8,
            });
        }
        let replaces = match best {
            None => true,
            Some(current) => {
                bid.price_atomic < current.price_atomic
                    || (bid.price_atomic == current.price_atomic
                        && bid.efficiency_pm > current.efficiency_pm)
                    || (bid.price_atomic == current.price_atomic
                        && bid.efficiency_pm == current.efficiency_pm
                        && bid.bidder < current.bidder)
            }
        };
        if replaces {
            best = Some(*bid);
        }
    }
    Ok(best)
}
