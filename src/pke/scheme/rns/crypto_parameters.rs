use crate::constants::{
    EncryptionTechnique, KeySwitchTechnique, MultiplicationTechnique, ScalingTechnique,
};
use crate::pke::scheme::rlwe::RLWECryptoParameters;

use crate::core::lattice::params::DcrtElementParams;
use derive_more::Display;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Display)]
#[display(
    "CryptoParametersRns {{\
 rlwe_crypto_parameters: {rlwe_crypto_parameters}, \
 key_switch_technique: {key_switch_technique}, \
 scaling_technique: {scaling_technique}, \
 encryption_technique: {encryption_technique}, \
 multiplication_technique: {multiplication_technique}, \
 aux_bits: {aux_bits}, \
 extra_bits: {extra_bits},\
 dcrt_element_params: {dcrt_element_params}"
)]
pub struct CryptoParametersRns {
    pub rlwe_crypto_parameters: RLWECryptoParameters,
    pub key_switch_technique: KeySwitchTechnique,
    pub scaling_technique: ScalingTechnique,
    pub encryption_technique: EncryptionTechnique,
    pub multiplication_technique: MultiplicationTechnique,
    pub aux_bits: usize,
    pub extra_bits: usize,
    pub dcrt_element_params: DcrtElementParams,
}
