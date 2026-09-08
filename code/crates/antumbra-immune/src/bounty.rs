//! The automatic bounty: a proof that replays is a payment that
//! clears, with no committee in the loop.

use crate::alert::Severity;
use crate::error::ImmuneError;

/// The base bounty of a critical first report: 250 ATU in atomic
/// units, scaled by severity and uniqueness.
pub const BOUNTY_BASE_ATOMIC: u64 = 25_000_000_000;

/// The treasury pole reserved for immunity bounties: forty
/// percent, per the v1.3 budget. Documentation constant: the
/// split itself is a rail A parameter, the pole is not.
pub const BOUNTY_POLE_PPM: u64 = 400_000;

/// The uniqueness factor of the first report of a proof hash, in
/// per mille.
pub const UNIQUENESS_FIRST_PM: u64 = 1_000;

/// The uniqueness factor of every later report of the same proof
/// hash: the repro documents, the discovery gets paid.
pub const UNIQUENESS_REPRO_PM: u64 = 250;

/// The bounty of an alert, in atomic units.
///
/// `bounty = base x severity_pm x uniqueness_pm / 1 000 000`,
/// floor division, every product checked: an overflow is a
/// validation error, never a wrap. The first reporter of a
/// replayable proof takes the full factor; the later ones are
/// documentation at a quarter. A market, not a committee: the
/// more powerful the attackers become, the more liquid this
/// market gets, and the shorter the life of a flaw.
///
/// # Errors
///
/// Returns [`ImmuneError::BountyOverflow`] if the intermediate
/// product does not fit the checked domain.
pub fn bounty(severity: Severity, first_report: bool) -> Result<u64, ImmuneError> {
    let uniqueness = if first_report {
        UNIQUENESS_FIRST_PM
    } else {
        UNIQUENESS_REPRO_PM
    };
    let product = u128::from(BOUNTY_BASE_ATOMIC)
        * u128::from(severity.bounty_factor_pm())
        * u128::from(uniqueness);
    let scaled = product / 1_000_000;
    if scaled > u128::from(u64::MAX) {
        return Err(ImmuneError::BountyOverflow { product });
    }
    Ok(scaled as u64)
}
