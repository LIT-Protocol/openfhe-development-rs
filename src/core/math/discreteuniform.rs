use crate::core::math::VecMod;
use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::{Concat, Odd, PrecomputeInverter, RandomMod, Split, Uint};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Debug, Copy, Clone)]
pub struct DiscreteUniform<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    pub(crate) modulus: Odd<Uint<LIMBS>>,
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    DiscreteUniform<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    pub fn new(modulus: Odd<Uint<LIMBS>>) -> Self {
        Self { modulus }
    }

    pub fn set_modulus(&mut self, modulus: Odd<Uint<LIMBS>>) {
        self.modulus = modulus;
    }

    pub fn gen_uint(&self) -> Uint<LIMBS> {
        Uint::<LIMBS>::random_mod(&mut StdRng::from_os_rng(), self.modulus.as_nz_ref())
    }

    pub fn gen_vec_mod(&self, length: usize) -> VecMod<LIMBS, WIDE_LIMBS> {
        VecMod::<LIMBS, WIDE_LIMBS>::random(StdRng::from_os_rng(), length, self.modulus)
    }

    pub fn gen_vec_mod_with_modulus(
        &mut self,
        length: usize,
        modulus: &Odd<Uint<LIMBS>>,
    ) -> VecMod<LIMBS, WIDE_LIMBS> {
        self.modulus = *modulus;
        VecMod::<LIMBS, WIDE_LIMBS>::random(StdRng::from_os_rng(), length, self.modulus)
    }
}
