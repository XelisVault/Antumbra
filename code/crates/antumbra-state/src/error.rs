//! The state error: every rule the ledger enforces, named.
//!
//! This module only re-exports [`StateError`]; the type lives in
//! [`crate::ledger`] beside the rules it reports, so that reading
//! the rules and reading their names stays one act.

pub use crate::ledger::StateError;
