use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod monty_params {
    use super::*;
    use crypto_bigint::{Concat, Encoding, Odd, Split, Uint, modular::MontyParams};
    use serde::de::Error;
    use subtle::CtOption;

    pub fn serialize<S: Serializer, const LIMBS: usize>(
        params: &MontyParams<LIMBS>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        Uint<LIMBS>: Encoding,
    {
        params.modulus().get().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const LIMBS: usize, const WIDE_LIMBS: usize>(
        deserializer: D,
    ) -> Result<MontyParams<LIMBS>, D::Error>
    where
        Uint<LIMBS>: Encoding + Concat<Output = Uint<WIDE_LIMBS>>,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        let modulus = Uint::<LIMBS>::deserialize(deserializer)?;
        let modulus = Option::<Odd<Uint<LIMBS>>>::from(CtOption::from(modulus.to_odd()))
            .ok_or(Error::custom("modulus is not odd"))?;
        Ok(MontyParams::new(modulus))
    }
}
