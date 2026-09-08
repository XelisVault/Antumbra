//! The code commitments: what a rollback returns to.

/// One hot code commitment: a version the network can run, with
/// the hashes that make it verifiable.
///
/// The nodes keep the last `N_HOT` versions warm: a rollback is
/// not a recompile, it is a switch back to the commitment that
/// was active before the failed upgrade.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CodeCommitment {
    /// The monotonically increasing version number.
    pub version: u32,
    /// The SHA-256 of the reproducible binary.
    pub sha256: [u8; 32],
    /// The hash of the Nix build that produced it, when the
    /// builder is capable of checking it.
    pub nix_hash: [u8; 32],
    /// The rail the version was activated through.
    pub rail: u8,
    /// The minimum height at which the version is valid.
    pub min_height: u32,
}

/// How many hot versions the nodes keep warm.
pub const N_HOT: usize = 3;

/// The rollback target: the most recent commitment before the
/// current one.
///
/// # Errors
///
/// Returns [`crate::error::ImmuneError::EmptyHistory`] when the history holds
/// fewer than two commitments: rolling back with nothing to
/// return to is a halt, not a rollback.
pub fn previous_hot(
    history: &[CodeCommitment],
) -> Result<CodeCommitment, crate::error::ImmuneError> {
    if history.len() < 2 {
        return Err(crate::error::ImmuneError::EmptyHistory);
    }
    Ok(history[history.len() - 2])
}
