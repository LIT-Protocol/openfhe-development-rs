use crate::constants::PlaintextEncodingsType;
use crate::crypto_object::CryptoObject;
use crate::pke::CryptoContext;
use crypto_bigint::U64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    crypto_context: CryptoContext,
    elements: Vec<U64>,
    noise_scale_degree: usize,
    encoding_type: PlaintextEncodingsType,
    scaling_factor: f64,
    scaling_factor_int: usize,
    level: usize,
    hops_level: usize,
}

impl Default for Ciphertext {
    fn default() -> Self {
        Self {
            crypto_context: CryptoContext::default(),
            elements: Vec::new(),
            noise_scale_degree: 1,
            encoding_type: PlaintextEncodingsType::default(),
            scaling_factor: 1.0,
            scaling_factor_int: 1,
            level: 0,
            hops_level: 0,
        }
    }
}

impl CryptoObject for Ciphertext {
    fn get_crypto_context(&self) -> &CryptoContext {
        unimplemented!()
    }
}

impl Ciphertext {}
