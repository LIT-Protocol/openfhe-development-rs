use crate::crypto_object::CryptoObject;
use crate::pke::CryptoContext;
use crypto_bigint::U64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalKey {
    crypto_context: CryptoContext,
    key: Vec<U64>,
}

impl CryptoObject for EvalKey {
    fn get_crypto_context(&self) -> &CryptoContext {
        &self.crypto_context
    }
}
