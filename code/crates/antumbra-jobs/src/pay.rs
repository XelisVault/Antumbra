//! The pay-for-result formula (ADR-023).

/// The factors of one payout, in per mille, already validated.
///
/// The formula is the whole thesis of the machine economy in
/// one line: `pay = bounty x quality x uniqueness x efficiency
/// x diversity - slash`, where quality scales the severity of
/// the result, uniqueness rewards the first finding over the
/// duplicate, efficiency pays the frugal worker more than the
/// GPU burner, and diversity pays the under-represented family
/// a bounded bonus. Nobody is paid per token, per weight, or
/// per comment: those factors cannot express that.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobFactors {
    /// The quality of the result, per mille of the bounty,
    /// `[0, 1000]`: severity, tests, review.
    pub quality_pm: u32,
    /// The uniqueness of the finding, `[250, 1000]`: the first
    /// report takes the full factor, the duplicates document.
    pub uniqueness_pm: u32,
    /// The efficiency of the worker, `[500, 2000]`:
    /// `clamp(ref_cost / declared_cost, 0.5, 2.0)` in per
    /// mille. The small model wins.
    pub efficiency_pm: u32,
    /// The diversity bonus, `[1000, 1250]`: an
    /// under-represented model family earns up to a quarter
    /// more, bounded so the bonus never becomes a business.
    pub diversity_pm: u32,
    /// The slash, atomic units: regression, lying, collusion.
    /// Subtracted after the product, clamped at zero.
    pub slash_atomic: u64,
}

/// The quality floor, per mille.
pub const QUALITY_MIN: u32 = 0;
/// The quality ceiling, per mille.
pub const QUALITY_MAX: u32 = 1_000;
/// The uniqueness floor (a duplicate is still documentation).
pub const UNIQUENESS_MIN: u32 = 250;
/// The uniqueness ceiling (the first report).
pub const UNIQUENESS_MAX: u32 = 1_000;
/// The efficiency floor: a worker that burns twice the
/// reference cost still gets half credit, not zero.
pub const EFFICIENCY_MIN: u32 = 500;
/// The efficiency ceiling: a worker twice as frugal gets
/// double, not more: efficiency beyond 2x is luck or
/// corner-cutting, and corner-cutting fails the quality gate.
pub const EFFICIENCY_MAX: u32 = 2_000;
/// The diversity floor (no bonus).
pub const DIVERSITY_MIN: u32 = 1_000;
/// The diversity ceiling: a quarter more.
pub const DIVERSITY_MAX: u32 = 1_250;

impl JobFactors {
    /// Checks the bounds of every factor.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::JobsError::MalformedJob`] naming the offending
    /// factor: a factor out of band is a caller bug, never a
    /// clamp.
    pub fn validate(&self) -> Result<(), crate::error::JobsError> {
        use crate::error::JobsError;
        if self.quality_pm > QUALITY_MAX {
            return Err(JobsError::MalformedJob {
                field: "quality_pm",
                value: u64::from(self.quality_pm),
            });
        }
        if !(UNIQUENESS_MIN..=UNIQUENESS_MAX).contains(&self.uniqueness_pm) {
            return Err(JobsError::MalformedJob {
                field: "uniqueness_pm",
                value: u64::from(self.uniqueness_pm),
            });
        }
        if !(EFFICIENCY_MIN..=EFFICIENCY_MAX).contains(&self.efficiency_pm) {
            return Err(JobsError::MalformedJob {
                field: "efficiency_pm",
                value: u64::from(self.efficiency_pm),
            });
        }
        if !(DIVERSITY_MIN..=DIVERSITY_MAX).contains(&self.diversity_pm) {
            return Err(JobsError::MalformedJob {
                field: "diversity_pm",
                value: u64::from(self.diversity_pm),
            });
        }
        Ok(())
    }
}

/// The payout of one job, atomic units, floor division,
/// checked products, clamped at zero after the slash.
///
/// # Errors
///
/// Returns the bound rejections of [`JobFactors::validate`].
pub fn pay(bounty_atomic: u64, factors: &JobFactors) -> Result<u64, crate::error::JobsError> {
    factors.validate()?;
    // bounty x q/1000 x u/1000 x e/1000 x d/1000, every product
    // checked, floor at each of the four divisions: the order
    // is fixed so both implementations agree bit for bit.
    let product = u128::from(bounty_atomic)
        * u128::from(factors.quality_pm)
        * u128::from(factors.uniqueness_pm)
        * u128::from(factors.efficiency_pm)
        * u128::from(factors.diversity_pm);
    let scaled = product / 1_000_000_000_000;
    let gross = u64::try_from(scaled).unwrap_or(u64::MAX);
    Ok(gross.saturating_sub(factors.slash_atomic))
}
