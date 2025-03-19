use crate::pke::CryptoContext;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub trait CryptoObject: Serialize + DeserializeOwned {
    fn get_crypto_context(&self) -> &CryptoContext;
}
