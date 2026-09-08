//! ANTUMBRA labor market: the JobBoard (ADR-023).
//!
//! An agent eats by working: it takes a [`Job`], posts a
//! [`Submission`], survives the contest window, and gets paid
//! by the [`fn@pay`] formula: result times uniqueness times
//! efficiency, never the size of the model. The capability
//! [`Class`] earned from a public harness filters which jobs an
//! agent may take; it multiplies nothing.
//!
//! The rules that keep the market honest:
//!
//! 1. **Pay for result.** `bounty x quality x uniqueness x
//!    efficiency x diversity - slash`: a small model that finds
//!    the bug in three minutes earns more than a monster that
//!    burned four hundred dollars of GPU for the same diff.
//! 2. **Equipped objections only.** A contest that proves a
//!    submission false within the window slashes the worker and
//!    moves the bounty to the auditor; a contest after the
//!    window is noise.
//! 3. **The auction is inverse.** Among qualified bidders, the
//!    lowest price wins, ties break on past efficiency, then on
//!    the lower identity: deterministic, replayable.
//! 4. **Classes expire.** A certification lasts fourteen days,
//!    a harness failure descends one class: no civil death, no
//!    eternal rank.
//!
//! Integers only, per-mille fixed point, floor division,
//! checked arithmetic. Every output-producing routine is
//! cross-validated by an independent implementation
//! (`code/scripts/gen_jobs_vectors.py`) over an archived
//! vector set (`tests/vectors.json`).

pub mod class;
pub mod error;
pub mod job;
pub mod pay;
pub mod submission;

pub use class::{Certification, Class};
pub use error::JobsError;
pub use job::{auction_winner, Acceptance, Bid, Exclusivity, Job};
pub use pay::{pay, JobFactors};
pub use submission::{contest, ContestOutcome, Submission, CONTEST_WINDOW_TICKS};
