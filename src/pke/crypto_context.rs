use crate::core::lattice::params::ElementParams;
use crate::encoding::EncodingParams;
use crypto_bigint::{Odd, U64};

use derive_more::Display;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Display, Deserialize, Serialize)]
#[display(
    "CryptoContext{{ element_params: {element_params}, encoding_params: {encoding_params} }}"
)]
pub struct CryptoContext {
    pub element_params: ElementParams,
    pub encoding_params: EncodingParams,
}

impl CryptoContext {
    pub fn plaintext_modulus(&self) -> Odd<U64> {
        self.encoding_params.plaintext_modulus
    }
}
