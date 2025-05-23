use crate::constants::PolynomialRingFormat;
use crate::core::lattice::params::ElementParams;
use crate::serdes::monty_params;
use std::marker::PhantomData;

use crate::ActingPrimitive;
use crate::core::math::{DiscreteGaussian, VecMod, VecModStd};
use crate::core::utils::reverse_bits;
use crypto_bigint::modular::{MontyParams, Retrieve};
use crypto_bigint::{Monty, NonZero, Odd, U64, modular::MontyForm};
use num::Integer;
use rand::distr::Distribution;
use rand::{Rng, RngCore};
use rand_distr::Normal;
use serde::{Deserialize, Serialize};
use std::ops::{
    Add, AddAssign, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Neg, Rem, RemAssign, Sub,
    SubAssign,
};
use subtle::CtOption;

macro_rules! poly_ops_variants {
    ($trait:ident, $func:ident, $op:tt, $traitassign:ident, $funcassign:ident, $opassign:tt, LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl $trait<$rhs> for $lhs {
            type Output = $out;

            fn $func(self, rhs: $rhs) -> Self::Output {
                &self $op &rhs
            }
        }

        impl $trait<&$rhs> for $lhs {
            type Output = $out;

            fn $func(self, rhs: &$rhs) -> Self::Output {
                &self $op rhs
            }
        }

        impl $trait<$rhs> for &$lhs {
            type Output = $out;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $op &rhs
            }
        }

        impl $trait<&$rhs> for &$lhs {
            type Output = $out;

            fn $func(self, rhs: &$rhs) -> Self::Output {
                let mut result = self.clone();
                result $opassign rhs;
                result
            }
        }

        impl $traitassign<$rhs> for $lhs {
            fn $funcassign(&mut self, rhs: $rhs) {
                *self $opassign &rhs;
            }
        }
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Poly {
    format: PolynomialRingFormat,
    params: ElementParams,
    values: VecModStd,
    #[serde(with = "monty_params")]
    monty_params_ciphertext_modulus: MontyParams<{ U64::LIMBS }>,
    #[serde(with = "monty_params")]
    monty_params_big_ciphertext_modulus: MontyParams<{ U64::LIMBS }>,
}

impl Index<usize> for Poly {
    type Output = U64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

impl IndexMut<usize> for Poly {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.values[index]
    }
}

impl Neg for Poly {
    type Output = Self;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl Neg for &Poly {
    type Output = Poly;

    fn neg(self) -> Self::Output {
        let mut result = self.clone();
        for i in result.values.iter_mut() {
            let ii = MontyForm::new(i, result.monty_params_ciphertext_modulus);
            *i = ii.neg().retrieve();
        }
        result
    }
}

poly_ops_variants!(Add, add, +, AddAssign, add_assign, +=, LHS = Poly, RHS = U64, Output = Poly);
poly_ops_variants!(Sub, sub, -, SubAssign, sub_assign, -=, LHS = Poly, RHS = U64, Output = Poly);
poly_ops_variants!(Mul, mul, *, MulAssign, mul_assign, *=, LHS = Poly, RHS = U64, Output = Poly);
poly_ops_variants!(Div, div, /, DivAssign, div_assign, /=, LHS = Poly, RHS = U64, Output = Poly);
poly_ops_variants!(Rem, rem, %, RemAssign, rem_assign, %=, LHS = Poly, RHS = Odd<U64>, Output = Poly);

poly_ops_variants!(Mul, mul, *, MulAssign, mul_assign, *=, LHS = Poly, RHS = (U64, U64), Output = Poly);

poly_ops_variants!(Add, add, +, AddAssign, add_assign, +=, LHS = Poly, RHS = Poly, Output = Poly);
poly_ops_variants!(Sub, sub, -, SubAssign, sub_assign, -=, LHS = Poly, RHS = Poly, Output = Poly);
poly_ops_variants!(Mul, mul, *, MulAssign, mul_assign, *=, LHS = Poly, RHS = Poly, Output = Poly);

impl AddAssign<&U64> for Poly {
    fn add_assign(&mut self, rhs: &U64) {
        let r = MontyForm::new(rhs, self.monty_params_ciphertext_modulus);
        match self.format {
            PolynomialRingFormat::Coefficient => {
                let e = MontyForm::new(&self.values[0], self.monty_params_ciphertext_modulus);
                self.values[0] = (e + r).retrieve();
            }
            PolynomialRingFormat::Evaluation => {
                for i in self.values.iter_mut() {
                    let ii = MontyForm::new(i, self.monty_params_ciphertext_modulus);
                    *i = (ii + r).retrieve();
                }
            }
        }
    }
}

impl SubAssign<&U64> for Poly {
    fn sub_assign(&mut self, rhs: &U64) {
        self.values -= rhs;
    }
}

impl MulAssign<&U64> for Poly {
    fn mul_assign(&mut self, rhs: &U64) {
        self.values *= rhs;
    }
}

impl MulAssign<&(U64, U64)> for Poly {
    fn mul_assign(&mut self, (p, q): &(U64, U64)) {
        // Perform multiply and divide
        *self = (&*self * p) / q;
    }
}

impl RemAssign<&Odd<U64>> for Poly {
    fn rem_assign(&mut self, rhs: &Odd<U64>) {
        self.values %= rhs;
    }
}

impl DivAssign<&U64> for Poly {
    fn div_assign(&mut self, rhs: &U64) {
        let r = MontyForm::new(rhs, self.monty_params_ciphertext_modulus);
        let r_inv = CtOption::from(r.inv()).expect("r is not zero");
        for e in self.values.iter_mut() {
            let i = MontyForm::new(e, self.monty_params_ciphertext_modulus);
            *e = (i * r_inv).retrieve();
        }
    }
}

impl AddAssign<&Poly> for Poly {
    fn add_assign(&mut self, rhs: &Self) {
        assert_eq!(self.params, rhs.params);
        assert_eq!(self.format, rhs.format);

        self.values += &rhs.values;
    }
}

impl SubAssign<&Poly> for Poly {
    fn sub_assign(&mut self, rhs: &Self) {
        assert_eq!(self.params, rhs.params);
        assert_eq!(self.format, rhs.format);

        self.values -= &rhs.values;
    }
}

impl MulAssign<&Poly> for Poly {
    fn mul_assign(&mut self, rhs: &Self) {
        let res = self.ntt() * rhs.ntt();
        *self = res.inv();
    }
}

impl Poly {
    pub fn discrete_gaussian(
        params: ElementParams,
        format: PolynomialRingFormat,
        discrete_gaussian: &mut DiscreteGaussian,
    ) -> Self {
        let mut res = Self {
            format: PolynomialRingFormat::Coefficient,
            params,
            values: discrete_gaussian
                .gen_vec_mod(params.ring_dimension, &params.ciphertext_modulus),
            monty_params_ciphertext_modulus: MontyParams::new(params.ciphertext_modulus),
            monty_params_big_ciphertext_modulus: MontyParams::new(params.big_ciphertext_modulus),
        };
        // res.set_format(format);
        res
    }

    pub fn format(&self) -> PolynomialRingFormat {
        self.format
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn modulus(&self) -> &Odd<U64> {
        &self.params.ciphertext_modulus
    }

    pub fn values(&self) -> &[U64] {
        self.values.as_ref()
    }

    pub fn set_values(&mut self, values: &[u64]) {
        let m = self.params.ciphertext_modulus.get().to_primitive();
        for (v, &val) in self.values.iter_mut().zip(values) {
            *v = U64::from_u64(val % m);
        }
    }

    pub fn cyclotomic_order(&self) -> usize {
        self.params.cyclotomic_order
    }

    /// Permutes coefficients in a polynomial. Moves the ith index to the
    /// first one, it only supports odd indices.
    ///
    /// # Arguments
    /// `k`: the element at `k` to perform the automorphism transform with
    /// `return`: the result of the automorphism transform
    pub fn automorphism_transform(&self, k: usize) -> Self {
        assert_eq!(k & 1, 1, "k must be odd");

        assert!(
            self.params.cyclotomic_order.is_power_of_two(),
            "Automorphism transform is only supported for power of two cyclotomic rings"
        );

        let log_m = (usize::BITS - self.params.cyclotomic_order.leading_zeros()) as usize;
        let log_n = log_m - 1;
        let mask = (1 << log_n) - 1;

        match self.format {
            PolynomialRingFormat::Evaluation => {
                let mut jk = k;

                let mut result = self.clone();

                for j in 1..self.params.ring_dimension {
                    let jrev = reverse_bits(j, log_n);
                    let idxrev = reverse_bits((jk >> 1) & mask, log_n);
                    result.values[jrev] = self.values[idxrev];
                    jk += 2 * k;
                }
                result
            }
            PolynomialRingFormat::Coefficient => {
                let mut result = self.clone();
                let mut jk = 0;
                let modulus = self.params.ciphertext_modulus.get();

                for j in 1..self.params.ring_dimension {
                    let idx = jk & mask;
                    result.values[idx] = if ((jk >> log_n) & 0x1) == 1 {
                        modulus - self.values[j]
                    } else {
                        self.values[j]
                    };

                    jk += k;
                }
                result
            }
        }
    }

    pub fn automorphism_transform_precompute(&self, k: usize, vec: &[usize]) -> Self {
        assert_eq!(k & 1, 1, "k must be odd");
        assert!(
            self.params.cyclotomic_order.is_power_of_two(),
            "Automorphism transform is only supported for power of two cyclotomic rings"
        );
        assert_eq!(
            self.format,
            PolynomialRingFormat::Evaluation,
            "Automorphism transform is only supported for evaluation format"
        );

        let mut result = self.clone();
        for (j, &idxrev) in vec.iter().enumerate() {
            result.values[j] = self.values[idxrev];
        }
        result
    }

    pub fn transpose(&self) -> Self {
        self.automorphism_transform(self.params.cyclotomic_order - 1)
    }

    pub fn base_decompose(&self, base_bits: usize, eval_mode_answer: bool) -> Vec<Self> {
        let m = self.params.ciphertext_modulus.bits() as usize;
        let (mut windows, remainder) = m.div_rem(&base_bits);
        if remainder != 0 {
            windows += 1;
        }

        let mut x_digit = Poly::zero(self.params);
        let mut result = Vec::with_capacity(windows);
        let mut x = self.clone();
        x.format = PolynomialRingFormat::Coefficient;

        for i in 0..windows {
            x_digit.format = x.format;
            let t = x.get_digit_at_index_for_base(i + 1, 1 << base_bits);
            x_digit.values.iter_mut().for_each(|x| *x = t);
            if eval_mode_answer {
                x_digit.switch_format();
            }
            result.push(x_digit.clone());
        }

        result
    }

    pub fn inverse(&self) -> Option<Self> {
        self.values.inverse().map(|values| Self {
            format: self.format,
            params: self.params,
            values,
            monty_params_ciphertext_modulus: self.monty_params_ciphertext_modulus,
            monty_params_big_ciphertext_modulus: self.monty_params_big_ciphertext_modulus,
        })
    }

    pub fn norm(&self) -> f64 {
        let q: u64 = self.params.ciphertext_modulus.get().to_primitive();
        let half = q >> 1;
        let mut max = 0;
        let mut min = q;

        for v in &self.values.values {
            let v = v.to_primitive();
            if v > half {
                min = std::cmp::min(v, min);
            } else {
                max = std::cmp::max(v, max);
            }
        }
        min = q - min;
        std::cmp::max(min, max) as f64
    }

    pub fn make_sparse(&mut self, w_factor: usize) {
        for i in 0..self.values.len() {
            if i % w_factor != 0 {
                self.values[i] = U64::ZERO;
            }
        }
    }

    pub fn mod_2(&self) -> Self {
        Self {
            format: self.format,
            params: self.params,
            values: self.values.rem_mod_2(),
            monty_params_ciphertext_modulus: self.monty_params_ciphertext_modulus,
            monty_params_big_ciphertext_modulus: self.monty_params_big_ciphertext_modulus,
        }
    }

    pub fn powers_of_base(&self, base_bits: usize) -> Vec<Self> {
        let m = self.params.ciphertext_modulus.bits() as usize;
        let (mut windows, remainder) = m.div_rem(&base_bits);
        if remainder != 0 {
            windows += 1;
        }
        let mut result = Vec::with_capacity(windows);
        let mut shift = U64::ZERO;
        let bbits = U64::from_u64(base_bits as u64);

        let two = MontyForm::new(&U64::from_u32(2), self.monty_params_ciphertext_modulus);
        for _ in 0..windows {
            let poly = self * two.pow(&shift).retrieve();
            result.push(poly);
            shift += bbits;
        }
        result
    }

    pub fn switch_modulus(
        &mut self,
        modulus: Odd<U64>,
        root_of_unity: U64,
        modulus_arb: Odd<U64>,
        root_of_unity_arb: U64,
    ) {
        self.params.ciphertext_modulus = modulus;
        self.params.root_of_unity = root_of_unity;
        self.params.big_ciphertext_modulus = modulus_arb;
        self.params.big_root_of_unity = root_of_unity_arb;
        self.monty_params_ciphertext_modulus = MontyParams::new(modulus);
        self.monty_params_big_ciphertext_modulus = MontyParams::new(modulus_arb);

        let m: NonZero<U64> = CtOption::from(modulus.to_nz()).expect("modulus is zero");
        for i in self.values.iter_mut() {
            *i %= m;
        }
    }

    pub fn switch_format(&mut self) {
        todo!()
    }

    pub fn zero(params: ElementParams) -> Self {
        Self {
            format: PolynomialRingFormat::default(),
            params,
            values: VecMod::with_value_uint(
                params.cyclotomic_order,
                U64::ZERO,
                params.ciphertext_modulus,
            ),
            monty_params_ciphertext_modulus: MontyParams::new(params.ciphertext_modulus),
            monty_params_big_ciphertext_modulus: MontyParams::new(params.big_ciphertext_modulus),
        }
    }

    pub fn set_zero(&mut self) {
        self.values.values.iter_mut().for_each(|d| *d = U64::ZERO);
    }

    pub fn max(params: ElementParams) -> Self {
        Self {
            format: PolynomialRingFormat::default(),
            params,
            values: VecMod::with_value_uint(
                params.cyclotomic_order,
                params.ciphertext_modulus.get() - U64::ONE,
                params.ciphertext_modulus,
            ),
            monty_params_ciphertext_modulus: MontyParams::new(params.ciphertext_modulus),
            monty_params_big_ciphertext_modulus: MontyParams::new(params.big_ciphertext_modulus),
        }
    }

    pub fn set_max(&mut self) {
        let m = self.params.ciphertext_modulus.get() - U64::ONE;
        self.values.values.iter_mut().for_each(|d| *d = m);
    }

    fn ntt(&self) -> NttPoly {
        let mut values = self
            .values
            .iter()
            .map(|v| MontyForm::<{ U64::LIMBS }>::new(v, self.monty_params_ciphertext_modulus))
            .collect::<Vec<_>>();

        bit_reverse_permutation(&mut values);

        // Compute NTT
        let mut m = U64::ONE;
        let root_of_unity = MontyForm::new(
            &self.params.root_of_unity,
            self.monty_params_ciphertext_modulus,
        );
        let order = self.params.cyclotomic_order;
        let cyclotomic_order = U64::from_u64(order as u64);
        while m < cyclotomic_order {
            let half_m: u64 = m.to_primitive();
            let half_m = half_m as usize;
            m <<= 1;

            let divisor = CtOption::from(m.to_nz()).expect("m is not zero");
            let exponent = cyclotomic_order / divisor;

            let omega_m = root_of_unity.pow(&exponent);
            let step: u64 = m.to_primitive();
            let step = step as usize;

            for k in (0..order).step_by(step) {
                let mut omega = MontyForm::one(self.monty_params_ciphertext_modulus);

                for j in 0..half_m {
                    let t = omega * values[k + j + half_m];
                    values[k + j + half_m] = values[k + j] - t;
                    values[k + j] += t;
                    omega *= omega_m;
                }
            }
        }

        NttPoly {
            format: self.format,
            params: self.params,
            values,
            monty_params_ciphertext_modulus: self.monty_params_ciphertext_modulus,
            monty_params_big_ciphertext_modulus: self.monty_params_big_ciphertext_modulus,
        }
    }

    fn get_digit_at_index_for_base(&self, index: usize, base: u64) -> U64 {
        let digit_length = base.ilog2() as usize;
        let mut digit = 0;
        let mut new_index = 1 + (index - 1) * digit_length;
        let mut i = 1u64;
        let value: u64 = self.values[index].to_primitive();
        while i < base {
            digit += ((value >> new_index) & 1) * i;
            new_index += 1;
            i <<= 1;
        }
        U64::from_u64(digit)
    }
}

// Bit-reverse permutation for NTT
fn bit_reverse_permutation(values: &mut [MontyForm<{ U64::LIMBS }>]) {
    let n = values.len();
    let bits = n.trailing_zeros() as usize;

    for i in 0..n {
        let rev = i.reverse_bits();
        if i < rev {
            values.swap(i, rev);
        }
    }
}

#[derive(Clone)]
struct NttPoly {
    format: PolynomialRingFormat,
    params: ElementParams,
    values: Vec<MontyForm<{ U64::LIMBS }>>,
    monty_params_ciphertext_modulus: MontyParams<{ U64::LIMBS }>,
    monty_params_big_ciphertext_modulus: MontyParams<{ U64::LIMBS }>,
}

poly_ops_variants!(Mul, mul, *, MulAssign, mul_assign, *=, LHS = NttPoly, RHS = NttPoly, Output = NttPoly);

impl MulAssign<&NttPoly> for NttPoly {
    fn mul_assign(&mut self, rhs: &NttPoly) {
        for (l, r) in self.values.iter_mut().zip(&rhs.values) {
            *l *= r;
        }
    }
}

impl NttPoly {
    pub fn inv(&self) -> Poly {
        let root_of_unity = MontyForm::<{ U64::LIMBS }>::new(
            &self.params.root_of_unity,
            self.monty_params_ciphertext_modulus,
        );
        let inv_root: MontyForm<{ U64::LIMBS }> =
            CtOption::from(root_of_unity.inv()).expect("root of unity is not zero");

        let mut values = self.values.clone();

        bit_reverse_permutation(&mut values);

        let mut m = U64::ONE;
        let order = self.params.cyclotomic_order;
        let cyclotomic_order = U64::from_u64(order as u64);
        while m < cyclotomic_order {
            let half_m: u64 = m.to_primitive();
            let half_m = half_m as usize;
            m <<= 1;

            let divisor = CtOption::from(m.to_nz()).expect("m is not zero");
            let exponent = cyclotomic_order / divisor;

            let omega_m = inv_root.pow(&exponent);
            let step: u64 = m.to_primitive();
            let step = step as usize;

            for k in (0..order).step_by(step) {
                let mut omega = MontyForm::one(self.monty_params_ciphertext_modulus);

                for j in 0..half_m {
                    let t = omega * values[k + j + half_m];
                    values[k + j + half_m] = values[k + j] - t;
                    values[k + j] += t;
                    omega *= omega_m;
                }
            }
        }

        let n = MontyForm::<{ U64::LIMBS }>::new(
            &cyclotomic_order,
            self.monty_params_ciphertext_modulus,
        );
        let n_inv = CtOption::from(n.inv()).expect("n is not zero");
        for i in values.iter_mut() {
            *i *= n_inv;
        }

        Poly {
            format: self.format,
            params: self.params,
            values: VecMod {
                values: values.iter().map(|v| v.retrieve()).collect(),
                params: self.monty_params_ciphertext_modulus,
                _marker: PhantomData,
            },
            monty_params_ciphertext_modulus: self.monty_params_ciphertext_modulus,
            monty_params_big_ciphertext_modulus: self.monty_params_big_ciphertext_modulus,
        }
    }
}
