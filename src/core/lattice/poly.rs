use crate::constants::PolynomialRingFormat;
use crate::core::lattice::IntType;
use crate::core::lattice::element::Element;
use crate::core::lattice::params::ElementParams;

use crate::core::utils::{compute_mu, mod_add_eq, mod_mul_eq, mod_sub_eq};
use serde::{Deserialize, Serialize};
use std::ops::{
    Add, AddAssign, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Neg, Rem, Sub, SubAssign,
};

macro_rules! poly_ops_variants {
    ($trait:ident, $func:ident, $op:tt, LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty, $($bounds:tt)+) => {
        impl<$($bounds)+> $trait<$rhs> for $lhs {
            type Output = $out;

            fn $func(self, rhs: $rhs) -> Self::Output {
                &self $op &rhs
            }
        }

        impl<$($bounds)+> $trait<&$rhs> for $lhs {
            type Output = $out;

            fn $func(self, rhs: &$rhs) -> Self::Output {
                &self $op rhs
            }
        }

        impl<$($bounds)+> $trait<$rhs> for &$lhs {
            type Output = $out;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $op &rhs
            }
        }

        impl<$($bounds)+> $trait<&$rhs> for &$lhs {
            type Output = $out;

            fn $func(self, rhs: &$rhs) -> Self::Output {
                let mut result = self.clone();
                result += rhs;
                result
            }
        }
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(bound = "I: IntType")]
pub struct Poly<I: IntType> {
    format: PolynomialRingFormat,
    params: ElementParams<I>,
    values: Vec<I>,
}

impl<I: IntType> Index<usize> for Poly<I> {
    type Output = I;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

impl<I: IntType> IndexMut<usize> for Poly<I> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.values[index]
    }
}

impl<I: IntType> Neg for Poly<I> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

poly_ops_variants!(Add, add, +, LHS = Poly<I>, RHS = I, Output = Poly<I>, I: IntType);
poly_ops_variants!(Sub, sub, -, LHS = Poly<I>, RHS = I, Output = Poly<I>, I: IntType);
poly_ops_variants!(Mul, mul, *, LHS = Poly<I>, RHS = I, Output = Poly<I>, I: IntType);

impl<I: IntType> Div<I> for Poly<I> {
    type Output = Self;

    fn div(self, rhs: I) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Rem<I> for Poly<I> {
    type Output = Self;

    fn rem(self, rhs: I) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> AddAssign<I> for Poly<I> {
    fn add_assign(&mut self, rhs: I) {
        *self += &rhs;
    }
}

impl<I: IntType> AddAssign<&I> for Poly<I> {
    fn add_assign(&mut self, rhs: &I) {
        let r = rhs.to_u64().expect("Failed to convert to u64");
        let m = self
            .params
            .ciphertext_modulus
            .to_u64()
            .expect("Failed to convert to u64");
        match self.format {
            PolynomialRingFormat::Coefficient => {
                let e = self.values[0].to_u64().expect("Failed to convert to u64");
                let i = mod_add_eq(e, r, m);
                self.values[0] = I::from_u64(i).expect("Failed to convert from u64");
            }
            PolynomialRingFormat::Evaluation => {
                for i in self.values.iter_mut() {
                    let ii = i.to_u64().expect("Failed to convert to u64");
                    let j = mod_add_eq(ii, r, m);
                    *i = I::from_u64(j).expect("Failed to convert from u64");
                }
            }
        }
    }
}

impl<I: IntType> SubAssign<I> for Poly<I> {
    fn sub_assign(&mut self, rhs: I) {
        *self -= &rhs;
    }
}

impl<I: IntType> SubAssign<&I> for Poly<I> {
    fn sub_assign(&mut self, rhs: &I) {
        let r = rhs.to_u64().expect("Failed to convert to u64");
        let m = self
            .params
            .ciphertext_modulus
            .to_u64()
            .expect("Failed to convert to u64");
        for e in self.values.iter_mut() {
            let i = e.to_u64().expect("Failed to convert to u64");
            let j = mod_sub_eq(i, r, m);
            *e = I::from_u64(j).expect("Failed to convert from u64");
        }
    }
}

impl<I: IntType> MulAssign<I> for Poly<I> {
    fn mul_assign(&mut self, rhs: I) {
        *self *= &rhs;
    }
}

impl<I: IntType> MulAssign<&I> for Poly<I> {
    fn mul_assign(&mut self, rhs: &I) {
        let r = rhs.to_u64().expect("Failed to convert to u64");
        let m = self
            .params
            .ciphertext_modulus
            .to_u64()
            .expect("Failed to convert to u64");
        let mu = compute_mu(m);
        for e in self.values.iter_mut() {
            let i = e.to_u64().expect("Failed to convert to u64");
            let j = mod_mul_eq(i, r, m, mu);
            *e = I::from_u64(j).expect("Failed to convert from u64");
        }
    }
}

impl<I: IntType> DivAssign<I> for Poly<I> {
    fn div_assign(&mut self, rhs: I) {
        todo!()
    }
}

impl<I: IntType> Add for Poly<I> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Add<&Poly<I>> for Poly<I> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Add<Poly<I>> for &Poly<I> {
    type Output = Poly<I>;

    fn add(self, rhs: Poly<I>) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Add for &Poly<I> {
    type Output = Self;

    fn add(self, rhs: &Poly<I>) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Sub for Poly<I> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Sub<&Poly<I>> for Poly<I> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Sub<Poly<I>> for &Poly<I> {
    type Output = Poly<I>;

    fn sub(self, rhs: Poly<I>) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Sub for &Poly<I> {
    type Output = Self;

    fn sub(self, rhs: &Poly<I>) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Mul for Poly<I> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Mul<&Poly<I>> for Poly<I> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Mul<Poly<I>> for &Poly<I> {
    type Output = Poly<I>;

    fn mul(self, rhs: Poly<I>) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> Mul for &Poly<I> {
    type Output = Poly<I>;

    fn mul(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<I: IntType> AddAssign for Poly<I> {
    fn add_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<I: IntType> AddAssign<&Poly<I>> for Poly<I> {
    fn add_assign(&mut self, rhs: &Self) {
        todo!()
    }
}

impl<I: IntType> SubAssign for Poly<I> {
    fn sub_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<I: IntType> SubAssign<&Poly<I>> for Poly<I> {
    fn sub_assign(&mut self, rhs: &Self) {
        todo!()
    }
}

impl<I: IntType> MulAssign for Poly<I> {
    fn mul_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<I: IntType> MulAssign<&Poly<I>> for Poly<I> {
    fn mul_assign(&mut self, rhs: &Self) {
        todo!()
    }
}

impl<I: IntType> Element for Poly<I> {
    type IntType = I;

    fn clone_empty(&self) -> Self {
        todo!()
    }

    fn clone_parameters(&self) -> Self {
        todo!()
    }

    fn clone_with_noise(&self) -> Self {
        todo!()
    }

    fn format(&self) -> PolynomialRingFormat {
        todo!()
    }

    fn len(&self) -> usize {
        todo!()
    }

    fn modulus(&self) -> Self::IntType {
        todo!()
    }

    fn values(&self) -> &[Self::IntType] {
        todo!()
    }

    fn cyclotomic_order(&self) -> usize {
        todo!()
    }

    fn add_assign_one(&mut self) {
        todo!()
    }

    fn automorphism_transform(&self, i: usize) -> Self {
        todo!()
    }

    fn automorphism_transform_precompute(&self, i: usize, vec: &[usize]) -> Self {
        todo!()
    }

    fn transpose(&self) -> Self {
        todo!()
    }

    fn base_decompose(&self, base_bits: usize, eval_mode_answer: bool) -> Vec<Self> {
        todo!()
    }

    fn inverse(&self) -> Option<Self> {
        todo!()
    }

    fn norm(&self) -> f64 {
        todo!()
    }

    fn make_sparse(&mut self, w_factor: usize) {
        todo!()
    }

    fn mod_2(&self) -> Self {
        todo!()
    }

    fn multiply_and_round(&self, p: Self::IntType, q: Self::IntType) -> Self {
        todo!()
    }

    fn powers_of_base(&self, base_bits: usize) -> Vec<Self> {
        todo!()
    }

    fn switch_modulus(
        &mut self,
        modulus: Self::IntType,
        root_of_unity: Self::IntType,
        modulus_arb: Self::IntType,
        root_of_unity_arb: Self::IntType,
    ) {
        todo!()
    }

    fn switch_format(&mut self) {
        todo!()
    }
}

impl<I: IntType> Poly<I> {
    pub fn zero(params: ElementParams<I>) -> Self {
        Self {
            format: PolynomialRingFormat::default(),
            params,
            values: vec![I::zero(); params.cyclotomic_order],
        }
    }

    pub fn max(params: ElementParams<I>) -> Self {
        Self {
            format: PolynomialRingFormat::default(),
            params,
            values: vec![params.ciphertext_modulus - I::one(); params.cyclotomic_order],
        }
    }
}
