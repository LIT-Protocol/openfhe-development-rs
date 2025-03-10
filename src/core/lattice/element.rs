use crate::constants::PolynomialRingFormat;
use crypto_bigint::{Odd, U64};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Div, DivAssign, Index, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

/// An ideal lattice element
///
/// Every lattice must implement this trait in order to properly
/// interact with PKE.
pub trait Element:
    Sized
    + Clone
    + Debug
    + PartialEq
    + Index<usize, Output = U64>
    + Neg                      // Unary negation on a lattice
    + Add<U64>
    + Sub<U64>
    + Mul<U64>
    + Div<U64>       // Scalar division and round
    + Rem<U64>       // Modulus operation
    + AddAssign<U64> // Scalar addition on a lattice
    + SubAssign<U64> // Scalar subtraction on a lattice
    + MulAssign<U64> // Scalar multiplication on a lattice
    + DivAssign<U64> // Scalar division and round on all entries
    + Add                      // Addition of two lattices
    + Sub                      // Subtraction of two lattices
    + Mul                      // Multiplication on a lattice
    + for<'a> Add<&'a Self>    // Addition of two lattices
    + for<'a> Sub<&'a Self>    // Addition of two lattices
    + for<'a> Mul<&'a Self>    // Addition of two lattices
    + AddAssign
    + SubAssign
    + MulAssign
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    /// Clone a new empty element
    fn clone_empty(&self) -> Self;

    /// Clone elements parameters but no elements
    fn clone_parameters(&self) -> Self;

    /// Clone the element with parameters and noise for the vector
    fn clone_with_noise(&self) -> Self;

    /// Get the format of the element
    fn format(&self) -> PolynomialRingFormat;

    /// Get the length of the element
    fn len(&self) -> usize;

    /// Get the modulus of the element
    fn modulus(&self) -> Odd<U64>;

    /// Get the values of the element
    fn values(&self) -> &[U64];

    /// Get the cyclotomic order
    fn cyclotomic_order(&self) -> U64;

    /// Adds one to every entry of the Element
    fn add_assign_one(&mut self);

    /// Performs an automorphism transform operation
    ///
    /// `i`: the element to perform the automorphism transform with
    fn automorphism_transform(&self, i: usize) -> Self;

    /// Performs an automorphism transform operation using precomputed-bit
    /// reversal indices
    ///
    /// `i`: the element to perform the automorphism transform with
    /// `vec`: the precomputed bit reversal indices
    fn automorphism_transform_precompute(&self, i: usize, vec: &[usize]) -> Self;

    /// Transpose the ring element using the automorphism operation
    fn transpose(&self) -> Self;

    /// Write the element as \sum_{i=0}^{\lfloor{\log q/base}\rfloor}{(base^i u_i)}
    /// and return the vector of
    /// \{u_0, u_1, \ldots, u_{\lfloor{\log q/base}\rfloor}\} \in R_{{base}^{\lceil{\log q/base}\rceil}}
    ///
    /// A subroutine in the relinearization procedure
    ///
    /// `base_bits`: number of bits in the base, i.e. base = 2^base_bits
    /// `eval_mode_answer`: if true, convert the result polynomials to evaluation mode
    fn base_decompose(&self, base_bits: usize, eval_mode_answer: bool) -> Vec<Self>;

    /// Calculate the multiplicative inverse if it exists.
    ///
    /// Returns [`None`] if no inverse exists
    fn inverse(&self) -> Option<Self>;

    /// Compute the infinity norm, the largest value in the ring element
    fn norm(&self) -> f64;

    /// True if the inner vector is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Make the element sparse for SHE key_gen operations.
    /// Sets every index not equal to zero mod the `w_factor` to zero.
    ///
    /// `w_factor`: ratio between the original element's ring dimension and the
    /// new ring dimension
    fn make_sparse(&mut self, w_factor: usize);

    /// Element mod 2
    fn mod_2(&self) -> Self;

    /// Scalar multiplication followed by division and rounding on all entries
    ///
    /// `p`: multiplicand
    /// `q`: divisor
    fn multiply_and_round(&self, p: U64, q: U64) -> Self;

    /// Calculate the vector of elements by raising the base element to successive powers
    fn powers_of_base(&self, base_bits: usize) -> Vec<Self>;

    /// Switch modulus and adjust the values
    ///
    /// `modulus`: the new modulus
    /// `root_of_unity`: the new root of unity for the new modulus
    /// `modulus_arb`: the new arbitrary cyclotomics CRT
    /// `root_of_unity_arb`: the new arbitrary cyclotomics CRT
    fn switch_modulus(
        &mut self,
        modulus: Odd<U64>,
        root_of_unity: U64,
        modulus_arb: Odd<U64>,
        root_of_unity_arb: U64,
    );

    /// Convert from coefficient to CRT or vice versa.
    fn switch_format(&mut self);

    /// Set the format of the element
    fn set_format(&mut self, format: PolynomialRingFormat) {
        if self.format() != format {
            self.switch_format();
        }
    }
}
