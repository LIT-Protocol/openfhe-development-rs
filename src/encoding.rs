//! Encoding parameters and plaintext polynomial types

use derive_more::{Display, FromStr, TryFrom};
use serde::{Deserialize, Serialize};

/// Parameters for encoding
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Display,
    Deserialize,
    Serialize,
)]
#[display(
    "Params {{ batch_size: {}, plaintext_generator: {}, plaintext_modulus: {}, plaintext_root_of_unity: {}, plaintext_big_modulus: {}, plaintext_big_root_of_unity: {} }}",
    batch_size,
    plaintext_generator,
    plaintext_modulus,
    plaintext_root_of_unity,
    plaintext_big_modulus,
    plaintext_big_root_of_unity
)]
pub struct Params {
    /// maximum batch size used by EvalSumKeyGen for packed encoding
    pub batch_size: usize,
    /// plaintext generator is used for packed encoding (to find the correct automorphism index)
    pub plaintext_generator: usize,
    /// plaintext modulus that is used by all schemes
    pub plaintext_modulus: u64,
    /// root of unity for plaintext modulus
    pub plaintext_root_of_unity: u128,
    /// big plaintext modulus that is used for arbitrary cyclotomics
    pub plaintext_big_modulus: u128,
    /// root of unity for big plaintext modulus
    pub plaintext_big_root_of_unity: u128,
}

/// Plaintext Polynomial Type
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, TryFrom, FromStr,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum PlaintextPolyType {
    /// Single-CRT representation using BigInteger types as coefficients,
    /// and supporting a large modulus q.
    #[default]
    IsPoly = 0,
    /// Double-CRT representation.
    ///
    /// In practice, this means that Poly uses a single large modulus q, while
    /// DCRTPoly uses multiple smaller moduli. Hence, Poly runs slower than
    /// DCRTPoly because DCRTPoly operations can be easier
    /// to fit into the native bit-widths of commodity processors.
    IsDcrtPoly,
    /// Single-CRT representation using NativeInteger types, which limits
    /// the size of the coefficients and the modulus q to 64 bits
    IsNativePoly,
}

hex_enum_usize!(PlaintextPolyType);
try_serde_str_or_u8!(PlaintextPolyType);
