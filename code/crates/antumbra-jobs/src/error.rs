//! One enum for every rejection of the labor market.

/// A failure of a JobBoard rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobsError {
    /// The Job is malformed: a bound, a mode or a vocabulary
    /// item violates the object grammar.
    MalformedJob {
        /// The offending field.
        field: &'static str,
        /// The offending value.
        value: u64,
    },
    /// A bid arrived from a bidder below the class floor of the
    /// job: the auction is for the qualified.
    UnderQualified {
        /// The class the job requires.
        class_min: u8,
    },
    /// A submission arrived for a job that is not open at that
    /// height: too early, too late, or not assigned to the
    /// submitter.
    NotOpen {
        /// The height of the attempt.
        height: u32,
    },
    /// The contest arrived outside the window: equipped or not,
    /// a late objection is noise.
    ContestClosed {
        /// The height of the attempt.
        height: u32,
    },
}

impl core::fmt::Display for JobsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedJob { field, value } => {
                write!(f, "malformed job: {field} = {value}")
            }
            Self::UnderQualified { class_min } => {
                write!(
                    f,
                    "the bidder is below class {class_min}: the auction is for the qualified"
                )
            }
            Self::NotOpen { height } => {
                write!(f, "the job is not open at height {height}")
            }
            Self::ContestClosed { height } => {
                write!(f, "the contest window is closed at height {height}")
            }
        }
    }
}

impl std::error::Error for JobsError {}
