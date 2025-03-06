use crypto_bigint::ConstZero;
use num::traits::{ConstOne, NumOps};
use num::{FromPrimitive, One, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    ops::{AddAssign, DivAssign, MulAssign, Neg, RemAssign, SubAssign},
};

pub mod element;
pub mod hal;
mod params;
mod poly;

/// General number type
pub trait IntType:
    Sized
    + Copy
    + Clone
    + Debug
    + Display
    + NumOps
    + One
    + ConstOne
    + Zero
    + ConstZero
    + Neg
    + AddAssign
    + SubAssign
    + MulAssign
    + DivAssign
    + RemAssign
    + PartialOrd
    + PartialEq
    + ToPrimitive
    + FromPrimitive
    + Serialize
    + for<'de> Deserialize<'de>
{
}

impl IntType for i8 {}
impl IntType for i16 {}
impl IntType for i32 {}
impl IntType for i64 {}
impl IntType for i128 {}
impl IntType for isize {}
impl IntType for f64 {}
impl IntType for f32 {}
