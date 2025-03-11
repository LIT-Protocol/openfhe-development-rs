use crypto_bigint::U64;
use derive_more::Display;
use serde::{Deserialize, Serialize};

use crate::constants::{
    MultipartyMode, ProxyPreEncryptionMode, SecretKeyDistribution, SecurityLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, Display)]
#[display(
    "RLWECryptoParameters {{ {discrete_gaussian_std_dev}, {discrete_gaussian_std_dev_with_flooding}, {assurance_measure_alpha}, {noise_scale}, {digit_size}, {max_relinearization_secret_key_power}, {secret_key_distribution}, {security_level}, {proxy_pre_encryption_mode}, {multiparty_mode}, {threshold_parties} }}"
)]
pub struct RLWECryptoParameters {
    /// discrete gaussian standard deviation
    pub discrete_gaussian_std_dev: f64,
    /// discrete gaussian standard deviation with flooding
    pub discrete_gaussian_std_dev_with_flooding: f64,
    /// assurance measure alpha
    pub assurance_measure_alpha: f64,
    /// noise scale
    pub noise_scale: U64,
    /// digit size
    pub digit_size: usize,
    /// the highest power of secret key for which relinearization key is generated
    pub max_relinearization_secret_key_power: usize,
    /// Whether secret polynomials are generated from a discrete Gaussian or
    /// a ternary distribution with the norm of unity
    pub secret_key_distribution: SecretKeyDistribution,
    /// The security level of the scheme
    pub security_level: SecurityLevel,
    /// The pre-encryption mode
    pub proxy_pre_encryption_mode: ProxyPreEncryptionMode,
    /// The multiparty mode
    pub multiparty_mode: MultipartyMode,
    /// The number of threshold parties
    pub threshold_parties: usize,
}

impl Default for RLWECryptoParameters {
    fn default() -> Self {
        Self {
            discrete_gaussian_std_dev: 0.0,
            discrete_gaussian_std_dev_with_flooding: 0.0,
            assurance_measure_alpha: 0.0,
            noise_scale: Default::default(),
            digit_size: 1,
            max_relinearization_secret_key_power: 2,
            secret_key_distribution: Default::default(),
            security_level: Default::default(),
            proxy_pre_encryption_mode: Default::default(),
            multiparty_mode: Default::default(),
            threshold_parties: 1,
        }
    }
}
