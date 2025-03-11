mod bfvrns;
mod rlwe;
mod rns;
mod utils;

use derive_more::{Display, FromStr, TryFrom};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr)]
#[repr(usize)]
pub enum Scheme {
    #[default]
    Invalid = 0,
    Ckks,
    Bfv,
    Bgv,
}

hex_enum_usize!(Scheme);

impl From<usize> for Scheme {
    fn from(value: usize) -> Self {
        match value {
            1 => Scheme::Ckks,
            2 => Scheme::Bfv,
            3 => Scheme::Bgv,
            _ => Scheme::Invalid,
        }
    }
}

serde_str_or_u8!(Scheme);
