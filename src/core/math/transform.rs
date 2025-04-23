use crate::core::math::vec_mod::*;
use crypto_bigint::*;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::RwLock;

#[derive(Debug, Copy, Clone, Hash)]
pub struct ModulusRoot<const LIMBS: usize>(Uint<LIMBS>, Uint<LIMBS>);

pub type ModulusRootStd = ModulusRoot<{ U64::LIMBS }>;

#[derive(Debug, Copy, Clone, Hash)]
pub struct ModulusRootPair<const LIMBS: usize>(ModulusRoot<LIMBS>, ModulusRoot<LIMBS>);

pub type ModulusRootPairStd = ModulusRootPair<{ U64::LIMBS }>;

pub mod number_theoretic_transform {
    use super::*;
    use crate::core::math::vec_mod::VecMod;
    use crate::core::utils::reverse_bits;
    use crypto_bigint::modular::SafeGcdInverter;
    use crypto_bigint::{Concat, MulMod, Split};

    pub fn forward_transform_iterative<
        const LIMBS: usize,
        const WIDE_LIMBS: usize,
        const UNSAT_LIMBS: usize,
    >(
        input: &VecMod<LIMBS, WIDE_LIMBS>,
        root_of_unity_table: &VecMod<LIMBS, WIDE_LIMBS>,
    ) -> VecMod<LIMBS, WIDE_LIMBS>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
    {
        let mut output = VecMod::with_value_uint(input.len(), Uint::ZERO, *input.params.modulus());
        let n = input.len();
        let msb = (u64::BITS - (n - 1).leading_zeros()) as usize;

        for i in 0..n {
            output[i] = input[reverse_bits(i, msb)];
        }

        let logn = msb;

        for logm in 1..=logn {
            let limit = 1 << (logm - 1);
            let mut indexes = Vec::with_capacity(limit);
            for i in 0..limit {
                indexes.push(i << (logn - logm));
            }

            for j in (0..n).step_by(1 << logm) {
                for i in 0..limit {
                    let omega = root_of_unity_table[indexes[i]];
                    let index_even = j + i;
                    let index_odd = index_even + limit;
                    let odd_val = output[index_odd];

                    let omega_factor = omega.mul_mod(&odd_val, input.params.modulus().as_nz_ref());
                    let mut even_val = output[index_even];
                    let mut odd_val = even_val + omega_factor;
                    if odd_val >= *input.params.modulus() {
                        odd_val -= input.params.modulus().get();
                    }

                    if even_val < omega_factor {
                        even_val += input.params.modulus().get();
                    }

                    even_val += omega_factor;

                    output[index_even] = even_val;
                    output[index_odd] = odd_val;
                }
            }
        }

        output
    }
}

pub mod chinese_remainder_transform_fft {
    use super::*;

    /// map to store the cyclo order inverse with modulus as a key
    /// For inverse FTT, we also need #m_cycloOrderInversePreconTableByModulus (this is to use an N-size NTT for FTT instead of 2N-size NTT).
    pub static CYCLOTOMIC_ORDER_INVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store the cyclo order inverse preconditioned with modulus as a key
    /// Shoup's precomputation of above #m_cycloOrderInverseTableByModulus
    pub static CYCLOTOMIC_ORDER_INVERSE_PRECONDITIONED_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store the forward roots of Unity for NTT, with bits reversed, with modulus as a key (aka twiddle factors)
    pub static ROOT_OF_UNITY_REVERSE_TABLE_BY_MODULUS: LazyLock<RwLock<HashMap<usize, VecModStd>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store inverse roots of unity for iNTT, with bits reversed, with modulus as a key (aka inverse twiddle factors)
    pub static ROOT_OF_UNITY_INVERSE_REVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store Shoup's precomputations of forward roots of unity for NTT, with bits reversed, with modulus as a key
    pub static ROOT_OF_UNITY_PRECONDITIONED_REVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store Shoup's precomputations of inverse rou for iNTT, with bits reversed, with modulus as a key
    pub static ROOT_OF_UNITY_INVERSE_PRECONDITIONED_REVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
}

pub mod bluestein_fft {
    use super::*;

    /// map to store the root of unity table with modulus as key.
    pub static ROOT_OF_UNITY_TABLE_BY_MODULUS_ROOT: LazyLock<
        RwLock<HashMap<ModulusRootStd, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the root of unity inverse table with modulus as key.
    pub static ROOT_OF_UNITY_INVERSE_TABLE_BY_MODULUS_ROOT: LazyLock<
        RwLock<HashMap<ModulusRootStd, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the power of roots as a table with modulus + root of unity as
    /// key.
    pub static POWERS_TABLE_BY_MODULUS_ROOT: LazyLock<RwLock<HashMap<ModulusRootStd, VecModStd>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the forward transform of power table with modulus + root of
    /// unity as key.
    pub static RB_TABLE_BY_MODULUS_ROOT_PAIR: LazyLock<
        RwLock<HashMap<ModulusRootPairStd, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the precomputed NTT modulus with modulus as key.
    pub static DEFAULT_NTT_MODULUS_ROOT: LazyLock<RwLock<HashMap<usize, ModulusRootStd>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
}

pub mod chinese_remainder_transform_arb {
    use super::*;

    /// map to store the cyclotomic polynomial with polynomial ring's modulus as
    /// key.
    pub static CYCLOTOMIC_POLY_MAP: LazyLock<RwLock<HashMap<usize, VecModStd>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the forward NTT transform of the inverse of cyclotomic
    /// polynomial with polynomial ring's modulus as key.
    pub static CYCLOTOMIC_POLY_REVERSE_NTT_MAP: LazyLock<RwLock<HashMap<usize, VecModStd>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the forward NTT transform of the cyclotomic polynomial with
    /// polynomial ring's modulus as key.
    pub static CYCLOTOMIC_POLY_NTT_MAP: LazyLock<RwLock<HashMap<usize, VecModStd>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the root of unity table used in NTT based polynomial division.
    pub static ROOT_OF_UNITY_DIVISION_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the root of unity table for computing forward NTT of inverse
    /// cyclotomic polynomial used in NTT based polynomial division.
    pub static ROOT_OF_UNITY_DIVISION_INVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, VecModStd>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));

    /// modulus used in NTT based polynomial division.
    pub static DIVISION_NTT_MODULUS: LazyLock<RwLock<HashMap<usize, usize>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// root of unity used in NTT based polynomial division.
    pub static DIVISION_NTT_ROOT_OF_UNITY: LazyLock<RwLock<HashMap<usize, usize>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// dimension of the NTT transform in NTT based polynomial division.
    pub static NTT_DIVISION_DIM: LazyLock<RwLock<HashMap<usize, usize>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
}
