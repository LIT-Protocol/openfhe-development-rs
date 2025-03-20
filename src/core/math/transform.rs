use crypto_bigint::U64;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::RwLock;

#[derive(Debug, Copy, Clone, Hash)]
pub struct ModulusRoot(U64, U64);

#[derive(Debug, Copy, Clone, Hash)]
pub struct ModulusRootPair(ModulusRoot, ModulusRoot);

pub mod number_theoretic_transform {
    use super::*;

    pub fn forward_transform_iterative(input: &[U64], root_of_unity_table: &[U64]) -> Vec<U64> {
        // let n = input.len();
        // let mut output = vec![U64::ZERO; n];
        // let mut omega = 1;
        // for i in 0..n {
        //     output[i] = input[i];
        // }
        // let mut t = 1;
        // while t < n {
        //     let t2 = t << 1;
        //     for i in (0..n).step_by(t2) {
        //         omega = 1;
        //         for j in 0..t {
        //             let temp = omega * output[i + j + t];
        //             output[i + j + t] = output[i + j] - temp;
        //             output[i + j] += temp;
        //             omega *= root_of_unity_table[n / t2 * j];
        //         }
        //     }
        //     t = t2;
        // }
        // output
        todo!()
    }
}

pub mod chinese_remainder_transform_fft {
    use super::*;

    /// map to store the cyclo order inverse with modulus as a key
    /// For inverse FTT, we also need #m_cycloOrderInversePreconTableByModulus (this is to use an N-size NTT for FTT instead of 2N-size NTT).
    pub static CYCLOTOMIC_ORDER_INVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store the cyclo order inverse preconditioned with modulus as a key
    /// Shoup's precomputation of above #m_cycloOrderInverseTableByModulus
    pub static CYCLOTOMIC_ORDER_INVERSE_PRECONDITIONED_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store the forward roots of Unity for NTT, with bits reversed, with modulus as a key (aka twiddle factors)
    pub static ROOT_OF_UNITY_REVERSE_TABLE_BY_MODULUS: LazyLock<RwLock<HashMap<usize, Vec<U64>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store inverse roots of unity for iNTT, with bits reversed, with modulus as a key (aka inverse twiddle factors)
    pub static ROOT_OF_UNITY_INVERSE_REVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store Shoup's precomputations of forward roots of unity for NTT, with bits reversed, with modulus as a key
    pub static ROOT_OF_UNITY_PRECONDITIONED_REVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
    /// map to store Shoup's precomputations of inverse rou for iNTT, with bits reversed, with modulus as a key
    pub static ROOT_OF_UNITY_INVERSE_PRECONDITIONED_REVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));
}

pub mod bluestein_fft {
    use super::*;

    /// map to store the root of unity table with modulus as key.
    pub static ROOT_OF_UNITY_TABLE_BY_MODULUS_ROOT: LazyLock<
        RwLock<HashMap<ModulusRoot, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the root of unity inverse table with modulus as key.
    pub static ROOT_OF_UNITY_INVERSE_TABLE_BY_MODULUS_ROOT: LazyLock<
        RwLock<HashMap<ModulusRoot, Vec<U64>>>,
    > = LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the power of roots as a table with modulus + root of unity as
    /// key.
    pub static POWERS_TABLE_BY_MODULUS_ROOT: LazyLock<RwLock<HashMap<ModulusRoot, Vec<U64>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the forward transform of power table with modulus + root of
    /// unity as key.
    pub static RB_TABLE_BY_MODULUS_ROOT_PAIR: LazyLock<RwLock<HashMap<ModulusRootPair, Vec<U64>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the precomputed NTT modulus with modulus as key.
    pub static DEFAULT_NTT_MODULUS_ROOT: LazyLock<RwLock<HashMap<usize, ModulusRoot>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
}

pub mod chinese_remainder_transform_arb {
    use super::*;

    /// map to store the cyclotomic polynomial with polynomial ring's modulus as
    /// key.
    pub static CYCLOTOMIC_POLY_MAP: LazyLock<RwLock<HashMap<usize, Vec<U64>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the forward NTT transform of the inverse of cyclotomic
    /// polynomial with polynomial ring's modulus as key.
    pub static CYCLOTOMIC_POLY_REVERSE_NTT_MAP: LazyLock<RwLock<HashMap<usize, Vec<U64>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the forward NTT transform of the cyclotomic polynomial with
    /// polynomial ring's modulus as key.
    pub static CYCLOTOMIC_POLY_NTT_MAP: LazyLock<RwLock<HashMap<usize, Vec<U64>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the root of unity table used in NTT based polynomial division.
    pub static ROOT_OF_UNITY_DIVISION_TABLE_BY_MODULUS: LazyLock<RwLock<HashMap<usize, Vec<U64>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// map to store the root of unity table for computing forward NTT of inverse
    /// cyclotomic polynomial used in NTT based polynomial division.
    pub static ROOT_OF_UNITY_DIVISION_INVERSE_TABLE_BY_MODULUS: LazyLock<
        RwLock<HashMap<usize, Vec<U64>>>,
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
