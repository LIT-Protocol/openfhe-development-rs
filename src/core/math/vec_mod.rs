use crypto_bigint::modular::{MontyForm, MontyParams, SafeGcdInverter};
use crypto_bigint::*;
use rand::CryptoRng;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DError, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};
use std::fmt::Formatter;
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

impl<const LIMBS: usize, const WIDE_LIMBS: usize> AsRef<[Uint<LIMBS>]> for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn as_ref(&self) -> &[Uint<LIMBS>] {
        &self.values
    }
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

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Serialize for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Serialize,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Serialize,
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("VecMod", 2)?;
        state.serialize_field("modulus", self.params.modulus())?;
        state.serialize_field("values", &self.values)?;
        state.end()
    }
}

impl<'de, const LIMBS: usize, const WIDE_LIMBS: usize> Deserialize<'de>
    for VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Deserialize<'de>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Deserialize<'de>,
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecModVisitor<'de, const LIMBS: usize, const WIDE_LIMBS: usize>
        where
            Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Deserialize<'de>,
            Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Deserialize<'de>,
        {
            _marker: PhantomData<&'de [(); WIDE_LIMBS]>,
        }

        enum Field {
            Values,
            Modulus,
        }
        const FIELDS: &[&str] = &["values", "modulus"];

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
                        write!(f, "`values` or `modulus`")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: DError,
                    {
                        match v {
                            "values" => Ok(Field::Values),
                            "modulus" => Ok(Field::Modulus),
                            _ => Err(DError::unknown_field(v, FIELDS)),
                        }
                    }
                }

                d.deserialize_identifier(FieldVisitor)
            }
        }

        impl<'de, const LIMBS: usize, const WIDE_LIMBS: usize> Visitor<'de>
            for VecModVisitor<'de, LIMBS, WIDE_LIMBS>
        where
            Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Deserialize<'de>,
            Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Deserialize<'de>,
        {
            type Value = VecMod<LIMBS, WIDE_LIMBS>;

            fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
                write!(f, "a modulus and values")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let modulus: Odd<Uint<LIMBS>> = seq
                    .next_element()?
                    .ok_or_else(|| DError::invalid_length(0, &self))?;
                let values: Vec<Uint<LIMBS>> = seq
                    .next_element()?
                    .ok_or_else(|| DError::invalid_length(1, &self))?;

                Ok(VecMod {
                    values,
                    params: MontyParams::new(modulus),
                    _marker: PhantomData,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = None;
                let mut modulus = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Values => {
                            if values.is_some() {
                                return Err(DError::duplicate_field("values"));
                            }

                            values = Some(map.next_value()?);
                        }
                        Field::Modulus => {
                            if modulus.is_some() {
                                return Err(DError::duplicate_field("modulus"));
                            }

                            modulus = Some(map.next_value()?);
                        }
                    }
                }

                let modulus: Odd<Uint<LIMBS>> =
                    modulus.ok_or_else(|| DError::missing_field("modulus"))?;
                let values: Vec<Uint<LIMBS>> =
                    values.ok_or_else(|| DError::missing_field("values"))?;
                Ok(VecMod {
                    values,
                    params: MontyParams::new(modulus),
                    _marker: PhantomData,
                })
            }
        }

        d.deserialize_struct(
            "VecMod",
            FIELDS,
            VecModVisitor::<LIMBS, WIDE_LIMBS> {
                _marker: PhantomData,
            },
        )
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    VecMod<LIMBS, WIDE_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
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

    pub fn inverse(&self) -> Option<Self> {
        let mut result = self.clone();
        if result.values.iter().any(|i| i.is_zero().into()) {
            return None;
        }
        result.values.iter_mut().for_each(|i| {
            let ct = i.inv_odd_mod(self.params.modulus());
            *i = ct.expect("to not fail since i is not zero");
        });
        Some(result)
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

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
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

    pub fn random(mut rng: impl CryptoRng, length: usize, modulus: Odd<Uint<LIMBS>>) -> Self {
        let nz_modulus = modulus.as_nz_ref();
        let mut values = Vec::with_capacity(length);
        for _ in 0..length {
            let value = Uint::<LIMBS>::random_mod(&mut rng, nz_modulus);
            values.push(value);
        }
        let params = MontyParams::new(modulus);
        Self {
            values,
            params,
            _marker: PhantomData,
        }
    }
}
