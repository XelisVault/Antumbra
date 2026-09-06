//! ANTUMBRA reputation layer: the Kleos machine (ADR-003,
//! ADR-015).
//!
//! Kleos is the consensus score that carries finality: a
//! three-layer total from 0 to 100, non-transferable,
//! non-purchasable, corroded by time. Reputation must be strong
//! enough to carry the Ring and sober enough never to become a
//! currency: the Deed (observed behavior, cap 40), the Echo
//! (peer attestations, cap 30), the Tenure (continuous
//! seniority, cap 30).
//!
//! Every quantity is a `u32` of millipoints and every operation
//! is integer arithmetic with floor rounding and saturating
//! bounds: two nodes holding the same events compute the same
//! score bit for bit, on any platform, forever. The simulation
//! of `simulations/` specified the rules in floats; this crate
//! is the normative integer implementation of the same rules.
//!
//! The same three rules as the primitives crate apply:
//!
//! 1. No silent defaults: construction validates bounds, a
//!    transition saturates exactly where the ADR says.
//! 2. Cross double implementation: every output-producing
//!    routine is reproduced independently
//!    (`code/scripts/gen_kleos_vectors.py`) over an archived
//!    vector set (`tests/vectors.json`); both must agree bit
//!    for bit.
//! 3. The state is pure: a transition is a function of the
//!    state and the era inputs, nothing else. The chain feeds
//!    the inputs; it never touches the arithmetic.

pub mod draw;
pub mod error;
pub mod score;

pub use draw::{draw, WordStream};
pub use error::KleosError;
pub use score::{
    capped_echo_gain, echo_contribution, mutual_echo, pooled_deed, EraInputs, Kleos, DEED_DECAY,
    DEED_MAX, ECHO_BUDGET, ECHO_DECAY, ECHO_MAX, ECHO_TARGET_CAP, RING_MIN_TENURE, RING_THRESHOLD,
    SPONSOR_PENALTY, TENURE_MAX, WITNESS_MIN_DEED, WITNESS_PENALTY, W_MIN,
};
