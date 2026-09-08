//! The bounded parameter registry of rail A.

use crate::error::ForgeError;

/// How many heights a parameter waits after a change before
/// the next one: no ping-ponging the fee floor.
pub const PARAM_COOLDOWN_HEIGHTS: u32 = 2_016;

/// One parameter of the registry: a key with its bounds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Parameter {
    /// The canonical key, as the chain archives it.
    pub key: &'static str,
    /// The floor of the band: a change below it is refused.
    pub min: u64,
    /// The ceiling of the band: a change above it is refused.
    pub max: u64,
    /// The live value.
    pub value: u64,
    /// The height of the last change.
    pub last_change_height: u32,
}

impl Parameter {
    /// The GHOSTDAG breadth, k: calibrated, never decreed, and
    /// confined to `[4, 16]` forever.
    #[must_use]
    pub const fn ghostdag_k() -> Self {
        Self {
            key: "ghostdag_k",
            min: 4,
            max: 16,
            value: 8,
            last_change_height: 0,
        }
    }

    /// The fee floor, in atomic units: a band, not a price.
    #[must_use]
    pub const fn fee_floor() -> Self {
        Self {
            key: "fee_floor_atomic",
            min: 100_000,
            max: 10_000_000,
            value: 1_000_000,
            last_change_height: 0,
        }
    }

    /// The ring size: the band of the anonymity set widths.
    #[must_use]
    pub const fn ring_size() -> Self {
        Self {
            key: "ring_size",
            min: 11,
            max: 24,
            value: 16,
            last_change_height: 0,
        }
    }

    /// The immunity share of the treasury, per mille: forty
    /// percent is the default the budget pins.
    #[must_use]
    pub const fn immunity_share() -> Self {
        Self {
            key: "treasury_immunity_share_pm",
            min: 200_000,
            max: 500_000,
            value: 400_000,
            last_change_height: 0,
        }
    }
}

/// The registry: the table the chain carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Registry {
    /// The parameters, in canonical order.
    pub entries: [Parameter; 4],
}

impl Default for Registry {
    /// The genesis registry, the same as [`Registry::genesis`].
    fn default() -> Self {
        Self::genesis()
    }
}

impl Registry {
    /// The genesis registry: the whitepaper defaults.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            entries: [
                Parameter::ghostdag_k(),
                Parameter::fee_floor(),
                Parameter::ring_size(),
                Parameter::immunity_share(),
            ],
        }
    }

    /// Applies a change attempt to the entry of `key`.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::OutOfBounds`] outside the band and
    /// [`ForgeError::Cooldown`] inside the cooldown of the last
    /// change: a senator cannot push a value where a
    /// constitutional vote alone may go, and the market cannot
    /// oscillate the fee faster than the cooldown.
    pub fn change(&mut self, key: &str, value: u64, at_height: u32) -> Result<(), ForgeError> {
        for entry in &mut self.entries {
            if entry.key != key {
                continue;
            }
            if !(entry.min..=entry.max).contains(&value) {
                return Err(ForgeError::OutOfBounds {
                    key: entry.key,
                    value,
                });
            }
            let until = entry
                .last_change_height
                .saturating_add(PARAM_COOLDOWN_HEIGHTS);
            if at_height < until && entry.last_change_height != 0 {
                return Err(ForgeError::Cooldown {
                    key: entry.key,
                    until,
                });
            }
            entry.value = value;
            entry.last_change_height = at_height;
            return Ok(());
        }
        Err(ForgeError::OutOfBounds {
            key: "unknown",
            value,
        })
    }
}

/// A one-shot change on a single parameter, for the vector set.
///
/// # Errors
///
/// Same rejections as [`Registry::change`].
pub fn change(entry: &mut Parameter, value: u64, at_height: u32) -> Result<(), ForgeError> {
    if !(entry.min..=entry.max).contains(&value) {
        return Err(ForgeError::OutOfBounds {
            key: entry.key,
            value,
        });
    }
    let until = entry
        .last_change_height
        .saturating_add(PARAM_COOLDOWN_HEIGHTS);
    if at_height < until && entry.last_change_height != 0 {
        return Err(ForgeError::Cooldown {
            key: entry.key,
            until,
        });
    }
    entry.value = value;
    entry.last_change_height = at_height;
    Ok(())
}
