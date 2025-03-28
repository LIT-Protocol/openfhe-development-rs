//! Constants used in the library

use bitflag::bitflag;
use derive_more::{Display, FromStr, TryFrom};

/// The maximum number of bits in a word
pub const MAX_BITS_IN_WORD: usize = 61;
/// The maximum log step
pub const MAX_LOG_STEP: usize = 60;
/// The maximum levels for discrete gaussian sampling
pub const MAX_DISCRETE_GAUSSIAN_LEVELS: usize = 4;
/// Most common value for levels/towers to drop
pub const BASE_NUM_LEVELS_TO_DROP: usize = 1;
/// Noise Flooding distribution parameter for distributed decryption in threshold FHE
pub const MP_SD: usize = 1048576;
/// Noise Flooding distribution parameter for fixed 20 bits noise multi-hop PRE
pub const PRE_SD: usize = 1048576;
/// Num of additional moduli in NOISE_FLOODING_MULTIPARTY mode
pub const NUM_MODULI_MULTIPARTY: usize = 2;
/// Modulus size for additional moduli in NOISE_FLOODING_MULTIPARTY mode
pub const MULTIPARTY_MOD_SIZE: usize = 60;
/// The maximum number of bits in modulus
pub const MAX_MODULUS_SIZE: usize = 60;

/// All features supported by public key encryption schemes
#[bitflag(usize)]
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Display,
    serde::Deserialize,
    serde::Serialize,
)]
pub enum PkeSchemeFeature {
    /// Public key encryption
    Pke = 0x01,
    /// Key switching
    KeySwitch = 0x02,
    /// Proxy Re-Encryption
    Pre = 0x04,
    /// Leveled Semi-Homomorphic-Encryption
    LeveledShe = 0x08,
    /// Advanced Semi-Homomorphic-Encryption
    AdvancedShe = 0x10,
    /// Multi-party computation
    MultiParty = 0x20,
    /// Fully Homomorphic Encryption
    Fhe = 0x40,
    /// Scheme switching
    SchemeSwitch = 0x80,
}

/// The scaling techniques
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr)]
#[repr(usize)]
pub enum ScalingTechnique {
    /// Fixed manual scaling
    #[default]
    FixedManual = 0,
    /// Fixed auto scaling
    FixedAuto,
    /// Flexible autoscaling
    FlexibleAuto,
    /// Flexible autoscaling extended
    FlexibleAutoExt,
    /// No rescale
    NoRescale,
    /// Invalid
    Invalid,
}

hex_enum_usize!(ScalingTechnique);

impl From<usize> for ScalingTechnique {
    fn from(value: usize) -> Self {
        match value {
            0 => ScalingTechnique::FixedManual,
            1 => ScalingTechnique::FixedAuto,
            2 => ScalingTechnique::FlexibleAuto,
            3 => ScalingTechnique::FlexibleAutoExt,
            4 => ScalingTechnique::NoRescale,
            _ => ScalingTechnique::Invalid,
        }
    }
}

serde_str_or_u8!(ScalingTechnique);

/// Proxy Pre-Encryption Mode
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr)]
#[repr(usize)]
pub enum ProxyPreEncryptionMode {
    /// Not set
    #[default]
    NotSet = 0,
    /// Ciphertext Indistinguishability
    IndCpa,
    /// Resistence against Honest Re-Encryption Attacks by incorporating fixed noise
    FixedNoiseHra,
    /// Resistence against Honest Re-Encryption Attacks by incorporating noise flooding
    NoiseFloodingHra,
}

hex_enum_usize!(ProxyPreEncryptionMode);

impl From<usize> for ProxyPreEncryptionMode {
    fn from(value: usize) -> Self {
        match value {
            0 => ProxyPreEncryptionMode::NotSet,
            1 => ProxyPreEncryptionMode::IndCpa,
            2 => ProxyPreEncryptionMode::FixedNoiseHra,
            3 => ProxyPreEncryptionMode::NoiseFloodingHra,
            _ => ProxyPreEncryptionMode::NotSet,
        }
    }
}

serde_str_or_u8!(ProxyPreEncryptionMode);

/// Multi-party mode
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr)]
#[repr(usize)]
pub enum MultipartyMode {
    /// Not valid
    Invalid = 0,
    /// Fixed noise mode
    #[default]
    FixedNoise,
    /// Noise flooding mode
    NoiseFlooding,
}

hex_enum_usize!(MultipartyMode);

impl From<usize> for MultipartyMode {
    fn from(value: usize) -> Self {
        match value {
            1 => MultipartyMode::FixedNoise,
            2 => MultipartyMode::NoiseFlooding,
            _ => MultipartyMode::Invalid,
        }
    }
}

serde_str_or_u8!(MultipartyMode);

/// Execution mode
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum ExecutionMode {
    /// Evaluation
    #[default]
    Evaluation = 0,
    /// Noise Estimation
    NoiseEstimation,
}

hex_enum_usize!(ExecutionMode);
try_serde_str_or_u8!(ExecutionMode);

/// Decryption noise mode
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum DecryptionNoiseMode {
    /// Fixed noise
    #[default]
    FixedNoise = 0,
    /// Noise flooding
    NoiseFlooding = 1,
}

hex_enum_usize!(DecryptionNoiseMode);
try_serde_str_or_u8!(DecryptionNoiseMode);

/// Key switch technique
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr)]
#[repr(usize)]
pub enum KeySwitchTechnique {
    /// Invalid
    #[default]
    Invalid = 0,
    /// Brakerski-Vaikuntanathan
    Bv,
    /// Hybrid
    Hybrid,
}

hex_enum_usize!(KeySwitchTechnique);

impl From<usize> for KeySwitchTechnique {
    fn from(value: usize) -> Self {
        match value {
            1 => KeySwitchTechnique::Bv,
            2 => KeySwitchTechnique::Hybrid,
            _ => KeySwitchTechnique::Invalid,
        }
    }
}

serde_str_or_u8!(KeySwitchTechnique);

/// Encryption Technique
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum EncryptionTechnique {
    /// Standard
    #[default]
    Standard = 0,
    /// Extended
    Extended,
}

hex_enum_usize!(EncryptionTechnique);
try_serde_str_or_u8!(EncryptionTechnique);

/// Multiplication Technique
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum MultiplicationTechnique {
    /// Behz
    #[default]
    Behz = 0,
    /// Hps
    Hps,
    /// Hps over Q
    HpsOverQ,
    /// Hps over Q leveled
    HpsOverQLeveled,
}

hex_enum_usize!(MultiplicationTechnique);
try_serde_str_or_u8!(MultiplicationTechnique);

/// Plaintext Encodings
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr)]
#[repr(usize)]
pub enum PlaintextEncodingsType {
    /// Invalid
    #[default]
    Invalid = 0,
    /// Coefficient packed
    CoefficientPacked,
    /// Packed
    Packed,
    /// String
    String,
    /// Ckks packed
    CkksPacked,
}

hex_enum_usize!(PlaintextEncodingsType);

impl From<usize> for PlaintextEncodingsType {
    fn from(value: usize) -> Self {
        match value {
            1 => PlaintextEncodingsType::CoefficientPacked,
            2 => PlaintextEncodingsType::Packed,
            3 => PlaintextEncodingsType::String,
            4 => PlaintextEncodingsType::CkksPacked,
            _ => PlaintextEncodingsType::Invalid,
        }
    }
}

serde_str_or_u8!(PlaintextEncodingsType);

/// Ciphertext Compression Levels
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum CompressionLevel {
    /// More efficient w/stronger security assumption
    #[default]
    Compact = 2,
    /// Less efficient w/weaker security assumption
    Slack = 3,
}

hex_enum_usize!(CompressionLevel);
try_serde_str_or_u8!(CompressionLevel);

/// RLWE key generation modes
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum SecretKeyDistribution {
    /// Gaussian
    Gaussian = 0,
    /// Uniform Ternary
    #[default]
    UniformTernary = 1,
    /// Sparse Ternary
    SparseTernary = 2,
}

hex_enum_usize!(SecretKeyDistribution);
try_serde_str_or_u8!(SecretKeyDistribution);

/// The polynomial ring format representation
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum PolynomialRingFormat {
    /// Evaluation
    #[default]
    Evaluation = 0,
    /// Coefficient
    Coefficient = 1,
}

hex_enum_usize!(PolynomialRingFormat);
try_serde_str_or_u8!(PolynomialRingFormat);

/// The Base Type for the Discrete Gaussian Sampler
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum BaseSamplerType {
    /// Knuth-Yao
    KnuthYao = 0,
    #[default]
    /// Peikert
    Peikert,
}

hex_enum_usize!(BaseSamplerType);
try_serde_str_or_u8!(BaseSamplerType);

#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr, TryFrom,
)]
#[try_from(repr)]
#[repr(usize)]
pub enum DistributionType {
    #[default]
    Uniform = 0,
    Error,
    Ternary,
}
hex_enum_usize!(DistributionType);
try_serde_str_or_u8!(DistributionType);

impl DistributionType {
    pub const NUM_VALUES: usize = 3;
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Display, FromStr)]
#[repr(usize)]
pub enum SecurityLevel {
    #[default]
    HeStdNotSet = 0,
    HeStd128Classic,
    HeStd192Classic,
    HeStd256Classic,
    HeStd128Quantum,
    HeStd192Quantum,
    HeStd256Quantum,
}

hex_enum_usize!(SecurityLevel);

impl From<usize> for SecurityLevel {
    fn from(value: usize) -> Self {
        match value {
            1 => SecurityLevel::HeStd128Classic,
            2 => SecurityLevel::HeStd192Classic,
            3 => SecurityLevel::HeStd256Classic,
            4 => SecurityLevel::HeStd128Quantum,
            5 => SecurityLevel::HeStd192Quantum,
            6 => SecurityLevel::HeStd256Quantum,
            _ => SecurityLevel::HeStdNotSet,
        }
    }
}

serde_str_or_u8!(SecurityLevel);

impl SecurityLevel {
    pub const NUM_VALUES: usize = 7;
}
