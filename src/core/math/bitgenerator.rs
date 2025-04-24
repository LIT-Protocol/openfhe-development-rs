use crate::core::math::VecMod;
use crypto_bigint::modular::{MontyParams, SafeGcdInverter};
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};
use rand::distr::Bernoulli;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::marker::PhantomData;

#[derive(Debug)]
pub struct BitGenerator {
    sequence: u32,
    counter: u32,
}

impl Default for BitGenerator {
    fn default() -> Self {
        BitGenerator {
            sequence: StdRng::from_os_rng().random::<u32>(),
            counter: 0,
        }
    }
}

impl BitGenerator {
    pub fn generate(&mut self) -> u16 {
        if self.counter == 0 {
            self.sequence = StdRng::from_os_rng().random::<u32>();
            self.counter = 32;
        }
        self.counter -= 1;
        ((self.sequence >> self.counter) & 1) as u16
    }

    pub fn gen_uint<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>(
        &self,
    ) -> Uint<LIMBS>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
    {
        let b = Bernoulli::new(0.5).unwrap();
        let s = StdRng::from_os_rng().sample(b);
        if s {
            Uint::<LIMBS>::ONE
        } else {
            Uint::<LIMBS>::ZERO
        }
    }

    pub fn gen_vec_mod<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>(
        &self,
        length: usize,
        modulus: &Odd<Uint<LIMBS>>,
    ) -> VecMod<LIMBS, WIDE_LIMBS>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
    {
        let b = Bernoulli::new(0.5).unwrap();
        let mut rng = StdRng::from_os_rng();
        let mut values = Vec::<Uint<LIMBS>>::with_capacity(length);

        for _ in 0..length {
            if rng.sample(b) {
                values.push(Uint::<LIMBS>::ONE);
            } else {
                values.push(Uint::<LIMBS>::ZERO);
            }
        }
        VecMod {
            values,
            params: MontyParams::new(*modulus),
            _marker: PhantomData,
        }
    }
}
