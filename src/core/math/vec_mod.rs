use crypto_bigint::modular::{MontyForm, MontyParams, SafeGcdInverter};
use crypto_bigint::*;
use std::marker::PhantomData;
use std::ops::{
    Add, AddAssign, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Rem, RemAssign, Sub, SubAssign,
};
use subtle::CtOption;

macro_rules! ops_impl {
    (
        $trait:ident,
        $func:ident,
        $op:tt,
        $trait_assign:ident,
        $func_assign:ident,
        $op_assign:tt,
        LHS = $lhs:ty,
        RHS = $rhs:ty,
        OUTPUT = $output:ty
        $(,)?
    ) => {
        impl<const LIMBS: usize, const WIDE_LIMBS: usize> $trait<$rhs> for $lhs
            where Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
                  Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        {
            type Output = $output;

            fn $func(self, rhs: $rhs) -> Self::Output {
                &self $op &rhs
            }
        }

        impl<const LIMBS: usize, const WIDE_LIMBS: usize> $trait<&$rhs> for $lhs
            where Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
                  Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        {
            type Output = $output;

            fn $func(self, rhs: &$rhs) -> Self::Output {
                &self $op rhs
            }
        }

        impl<const LIMBS: usize, const WIDE_LIMBS: usize> $trait<$rhs> for &$lhs
            where Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
                  Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        {
            type Output = $output;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $op &rhs
            }
        }

        impl<const LIMBS: usize, const WIDE_LIMBS: usize> $trait<&$rhs> for &$lhs
            where Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
                  Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        {
            type Output = $output;

            fn $func(self, rhs: &$rhs) -> Self::Output {
                let mut result = self.clone();
                result $op_assign rhs;
                result
            }
        }

        impl<const LIMBS: usize, const WIDE_LIMBS: usize> $trait_assign<$rhs> for $lhs
            where Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
                  Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        {
            fn $func_assign(&mut self, rhs: $rhs) {
                self.$func_assign(&rhs);
            }
        }
    };
}

pub type VecModStd = VecMod<{ U64::LIMBS }, { U128::LIMBS }>;

#[derive(Debug, Clone)]
pub struct VecMod<const LIMBS: usize, const WIDE_LIMBS: usize>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    pub values: Vec<Uint<LIMBS>>,
    pub params: MontyParams<LIMBS>,
    pub _marker: PhantomData<[(); WIDE_LIMBS]>,
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Index<usize> for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = Uint<LIMBS>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> IndexMut<usize> for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.values[index]
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Eq for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> PartialEq for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values && self.params == other.params
    }
}

ops_impl!(
    Add,
    add,
    +,
    AddAssign,
    add_assign,
    +=,
    LHS = VecMod<LIMBS, WIDE_LIMBS>,
    RHS = Uint<LIMBS>,
    OUTPUT = VecMod<LIMBS, WIDE_LIMBS>,
);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> AddAssign<&Uint<LIMBS>>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn add_assign(&mut self, rhs: &Uint<LIMBS>) {
        let m = self.params.modulus().get();
        self.values
            .iter_mut()
            .for_each(|it| *it = it.add_mod(rhs, &m));
    }
}

ops_impl!(
    Add,
    add,
    +,
    AddAssign,
    add_assign,
    +=,
    LHS = VecMod<LIMBS, WIDE_LIMBS>,
    RHS = VecMod<LIMBS, WIDE_LIMBS>,
    OUTPUT = VecMod<LIMBS, WIDE_LIMBS>,
);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> AddAssign<&VecMod<LIMBS, WIDE_LIMBS>>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn add_assign(&mut self, rhs: &VecMod<LIMBS, WIDE_LIMBS>) {
        assert_eq!(self.params, rhs.params);
        let m = self.params.modulus().get();
        self.values
            .iter_mut()
            .zip(rhs.values.iter())
            .for_each(|(it, rhs)| {
                *it = it.add_mod(rhs, &m);
            });
    }
}

ops_impl!(
    Sub,
    sub,
    -,
    SubAssign,
    sub_assign,
    -=,
    LHS = VecMod<LIMBS, WIDE_LIMBS>,
    RHS = Uint<LIMBS>,
    OUTPUT = VecMod<LIMBS, WIDE_LIMBS>,
);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> SubAssign<&Uint<LIMBS>>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn sub_assign(&mut self, rhs: &Uint<LIMBS>) {
        let m = self.params.modulus().get();
        self.values
            .iter_mut()
            .for_each(|it| *it = it.sub_mod(rhs, &m));
    }
}

ops_impl!(
    Sub,
    sub,
    -,
    SubAssign,
    sub_assign,
    -=,
    LHS = VecMod<LIMBS, WIDE_LIMBS>,
    RHS = VecMod<LIMBS, WIDE_LIMBS>,
    OUTPUT = VecMod<LIMBS, WIDE_LIMBS>,
);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> SubAssign<&VecMod<LIMBS, WIDE_LIMBS>>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn sub_assign(&mut self, rhs: &VecMod<LIMBS, WIDE_LIMBS>) {
        assert_eq!(self.params, rhs.params);
        let m = self.params.modulus().get();
        self.values
            .iter_mut()
            .zip(rhs.values.iter())
            .for_each(|(it, rhs)| {
                *it = it.sub_mod(rhs, &m);
            });
    }
}

ops_impl!(
    Mul,
    mul,
    *,
    MulAssign,
    mul_assign,
    *=,
    LHS = VecMod<LIMBS, WIDE_LIMBS>,
    RHS = Uint<LIMBS>,
    OUTPUT = VecMod<LIMBS, WIDE_LIMBS>,
);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> MulAssign<&Uint<LIMBS>>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &Uint<LIMBS>) {
        let m = self.params.modulus().as_nz_ref();
        self.values
            .iter_mut()
            .for_each(|it| *it = it.mul_mod(rhs, m));
    }
}

ops_impl!(
    Mul,
    mul,
    *,
    MulAssign,
    mul_assign,
    *=,
    LHS = VecMod<LIMBS, WIDE_LIMBS>,
    RHS = VecMod<LIMBS, WIDE_LIMBS>,
    OUTPUT = VecMod<LIMBS, WIDE_LIMBS>,
);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> MulAssign<&VecMod<LIMBS, WIDE_LIMBS>>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn mul_assign(&mut self, rhs: &VecMod<LIMBS, WIDE_LIMBS>) {
        assert_eq!(self.params, rhs.params);
        let m = self.params.modulus().as_nz_ref();
        self.values
            .iter_mut()
            .zip(rhs.values.iter())
            .for_each(|(it, rhs)| {
                *it = it.mul_mod(rhs, m);
            });
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    Div<NonZero<Uint<LIMBS>>> for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    type Output = Self;

    fn div(self, rhs: NonZero<Uint<LIMBS>>) -> Self::Output {
        &self / &rhs
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    Div<&NonZero<Uint<LIMBS>>> for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    type Output = Self;

    fn div(self, rhs: &NonZero<Uint<LIMBS>>) -> Self::Output {
        &self / rhs
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    Div<NonZero<Uint<LIMBS>>> for &VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    type Output = VecMod<LIMBS, WIDE_LIMBS>;

    fn div(self, rhs: NonZero<Uint<LIMBS>>) -> Self::Output {
        self / &rhs
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    Div<&NonZero<Uint<LIMBS>>> for &VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    type Output = VecMod<LIMBS, WIDE_LIMBS>;

    fn div(self, rhs: &NonZero<Uint<LIMBS>>) -> Self::Output {
        let mut result = self.clone();
        result.div_assign(rhs);
        result
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    DivAssign<NonZero<Uint<LIMBS>>> for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    fn div_assign(&mut self, rhs: NonZero<Uint<LIMBS>>) {
        self.div_assign(&rhs);
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    DivAssign<&NonZero<Uint<LIMBS>>> for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    fn div_assign(&mut self, rhs: &NonZero<Uint<LIMBS>>) {
        let rhs_inv = CtOption::from(rhs.get().inv_odd_mod(self.params.modulus()))
            .expect("to not fail since rhs is not zero");
        *self *= &rhs_inv;
    }
}

ops_impl!(
    Rem,
    rem,
    %,
    RemAssign,
    rem_assign,
    %=,
    LHS = VecMod<LIMBS, WIDE_LIMBS>,
    RHS = Odd<Uint<LIMBS>>,
    OUTPUT = VecMod<LIMBS, WIDE_LIMBS>,
);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> RemAssign<&Odd<Uint<LIMBS>>>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn rem_assign(&mut self, modulus: &Odd<Uint<LIMBS>>) {
        let new_modulus = modulus.get();
        let old_modulus = self.params.modulus().get();
        let half_q = old_modulus >> 1;

        if new_modulus > old_modulus {
            let diff = new_modulus - old_modulus;
            self.values.iter_mut().for_each(|x| {
                if *x > half_q {
                    *x += diff;
                }
            });
        } else {
            let nz_modulus = modulus.as_nz_ref();
            let diff = new_modulus - old_modulus.rem(nz_modulus);
            self.values.iter_mut().for_each(|x| {
                if *x > half_q {
                    *x += diff;
                }
                if *x >= new_modulus {
                    *x = x.rem(nz_modulus);
                }
            });
        }
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    pub fn with_value_uint(len: usize, value: Uint<LIMBS>, modulus: Odd<Uint<LIMBS>>) -> Self {
        let nz_modulus = modulus.as_nz_ref();
        let values = vec![value.rem(nz_modulus); len];
        let params = MontyParams::new(modulus);
        Self {
            values,
            params,
            _marker: PhantomData,
        }
    }

    pub fn with_values_usize(values: &[usize], modulus: Odd<Uint<LIMBS>>) -> Self {
        let nz_modulus = modulus.as_nz_ref();
        let values = values
            .iter()
            .map(|x| Uint::from_u64(*x as u64).rem(nz_modulus))
            .collect::<Vec<_>>();
        let params = MontyParams::new(modulus);
        Self {
            values,
            params,
            _marker: PhantomData,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Uint<LIMBS>> {
        self.values.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Uint<LIMBS>> {
        self.values.iter_mut()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn rem_mod_2(&self) -> Self {
        let mut result = self.clone();
        result.rem_mod_2_assign();
        result
    }

    pub fn rem_mod_2_assign(&mut self) {
        let modulus = self.params.modulus().get();
        let half_q = modulus >> 1;
        self.values.iter_mut().for_each(|x| {
            let bit = if *x > half_q { Uint::ONE } else { Uint::ZERO };
            *x = Uint::ONE & (*x ^ bit);
        });
    }

    pub fn pow(&self, exponent: &Uint<LIMBS>) -> Self {
        let mut result = self.clone();
        result.pow_assign(exponent);
        result
    }

    pub fn pow_assign(&mut self, exponent: &Uint<LIMBS>) {
        self.values.iter_mut().for_each(|it| {
            let t = MontyForm::new(it, self.params);
            *it = t.pow(exponent).retrieve();
        })
    }

    pub fn modulus(&self) -> &Odd<Uint<LIMBS>> {
        self.params.modulus()
    }

    pub fn switch_modulus(&mut self, modulus: Odd<Uint<LIMBS>>) {
        *self %= &modulus;
        self.params = MontyParams::new(modulus);
    }
}
