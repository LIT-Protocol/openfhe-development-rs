use crate::core::lattice::params::ElementParams;
use crate::encoding::{EncodingParams, PlaintextEncodings};
use crypto_bigint::{Odd, U64};
use std::sync::RwLock;

use crate::constants::PlaintextEncodingsType;
use derive_more::Display;
use serde::{Deserialize, Serialize};

pub(crate) static ALL_CRYPTO_CONTEXTS: RwLock<Vec<CryptoContext>> = RwLock::new(Vec::new());

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Display, Deserialize, Serialize)]
#[display(
    "CryptoContext{{ element_params: {element_params}, encoding_params: {encoding_params} }}"
)]
pub struct CryptoContext {
    pub element_params: ElementParams,
    pub encoding_params: EncodingParams,
}

impl CryptoContext {
    pub fn make_plaintext(
        &self,
        encoding: PlaintextEncodingsType,
        value: &[isize],
        depth: usize,
        level: usize,
    ) -> PlaintextEncodings {
        todo!()
    }
}
