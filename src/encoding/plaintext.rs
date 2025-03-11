use crate::ActingPrimitive;
use crate::core::lattice::poly::Poly;
use crate::encoding::EncodingParams;
use derive_more::Display;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum PlaintextEncodings {
    Packed(PackedPlaintext),
    Coefficient(CoefficientPlaintext),
    String(StringPlaintext),
    Ckks(CkksPlaintext),
}

impl PlaintextEncodings {
    pub fn params(&self) -> &PlaintextParams {
        match self {
            PlaintextEncodings::Packed(p) => &p.encoding_params,
            PlaintextEncodings::Coefficient(p) => &p.encoding_params,
            PlaintextEncodings::String(p) => &p.encoding_params,
            PlaintextEncodings::Ckks(p) => &p.encoding_params,
        }
    }

    pub fn lower_bound(&self) -> isize {
        let modulus = self
            .params()
            .encoding_params
            .plaintext_modulus
            .get()
            .to_primitive();
        let half = modulus >> 1;
        -(half as isize)
    }

    pub fn upper_bound(&self) -> isize {
        let modulus = self
            .params()
            .encoding_params
            .plaintext_modulus
            .get()
            .to_primitive();
        let half = modulus >> 1;
        half as isize
    }
}

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Display, Deserialize, Serialize)]
#[display(
    "BasePlaintextParams {{ scaling_factor: {scaling_factor}, level: {level}, noise_scale_degree: {noise_scale_degree}, slots: {slots}, encoding_params: {encoding_params} }}"
)]
pub struct PlaintextParams {
    pub scaling_factor: f64,
    pub scaling_factor_int: usize,
    pub level: usize,
    pub noise_scale_degree: usize,
    pub slots: usize,
    pub encoding_params: EncodingParams,
}

impl Default for PlaintextParams {
    fn default() -> Self {
        Self {
            scaling_factor: 1.0,
            scaling_factor_int: 1,
            level: 0,
            noise_scale_degree: 0,
            slots: 0,
            encoding_params: EncodingParams::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackedPlaintext {
    value: Vec<u64>,
    encoded_value: Poly,
    encoding_params: PlaintextParams,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoefficientPlaintext {
    value: Vec<u64>,
    encoded_value: Poly,
    encoding_params: PlaintextParams,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringPlaintext {
    value: String,
    encoded_value: Poly,
    encoding_params: PlaintextParams,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CkksPlaintext {
    value: Vec<f64>,
    encoded_value: Poly,
    encoding_params: PlaintextParams,
}
