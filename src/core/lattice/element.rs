use crate::constants::{MAX_MODULUS_SIZE, PolynomialRingFormat};
use crate::core::lattice::IntType;
use crate::core::utils::{fermat, get_totient, miller_rabin, previous_prime, root_of_unity};
use crate::error::{Error, Result};
use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::ops::{
    Add, AddAssign, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Neg, Rem, Sub, SubAssign,
};

/// An ideal lattice element
///
/// Every lattice must implement this trait in order to properly
/// interact with PKE.
pub trait Element:
    Sized
    + Clone
    + Eq
    + PartialEq
    + Index<usize, Output = Self::IntType>
    + Neg                      // Unary negation on a lattice
    + Add<Self::IntType>
    + Sub<Self::IntType>
    + Mul<Self::IntType>
    + Div<Self::IntType>       // Scalar division and round
    + Rem<Self::IntType>       // Modulus operation
    + AddAssign<Self::IntType> // Scalar addition on a lattice
    + SubAssign<Self::IntType> // Scalar subtraction on a lattice
    + MulAssign<Self::IntType> // Scalar multiplication on a lattice
    + DivAssign<Self::IntType> // Scalar division and round on all entries
    + MulAssign<i8>            // Scalar multiplication by a signed integer
    + MulAssign<i16>
    + MulAssign<i32>
    + MulAssign<i64>
    + MulAssign<isize>
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
    /// The number type
    type IntType: IntType;

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
    fn modulus(&self) -> Self::IntType;

    /// Get the values of the element
    fn values(&self) -> &[Self::IntType];

    /// Get the cyclotomic order
    fn cyclotomic_order(&self) -> usize;

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
    fn multiply_and_round(&self, p: Self::IntType, q: Self::IntType) -> Self;

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
        modulus: Self::IntType,
        root_of_unity: Self::IntType,
        modulus_arb: Self::IntType,
        root_of_unity_arb: Self::IntType,
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

/// Parameters for an element
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Display, Serialize, Deserialize)]
#[display(
    "ElementParams {{ ring_dimension: {}, cyclotomic_order: {}, ciphertext_modulus: {}, root_of_unity: {}, big_ciphertext_modulus: {}, big_root_of_unity: {} }}",
    ring_dimension,
    cyclotomic_order,
    ciphertext_modulus,
    root_of_unity,
    big_ciphertext_modulus,
    big_root_of_unity
)]
#[serde(bound = "I: IntType")]
pub struct ElementParams<I: IntType> {
    /// The ring dimension
    pub ring_dimension: usize,
    /// The cyclotomic order
    pub cyclotomic_order: usize,
    /// The ciphertext modulus
    pub ciphertext_modulus: I,
    /// The ciphertext modulus root of unity
    pub root_of_unity: I,
    /// The big ciphertext modulus used for bit-packing operations
    pub big_ciphertext_modulus: I,
    /// The big ciphertext modulus root of unity
    pub big_root_of_unity: I,
}

impl<I: IntType> ElementParams<I> {
    pub fn with_modulus_bits(order: usize, bits: usize) -> Self {
        if bits > MAX_MODULUS_SIZE {
            panic!(
                "Requested bit length {} exceeds maximum allowed length {}",
                bits, MAX_MODULUS_SIZE
            );
        }

        let modulus =
            I::from_u64(previous_prime(1u64 << bits)).expect("modulus is not compatible with u64");
        Self::with_modulus(order, modulus)
    }

    pub fn with_modulus(order: usize, ciphertext_modulus: I) -> Self {
        let modulus = ciphertext_modulus
            .to_usize()
            .expect("modulus is not compatible with usize");
        let root_of_unity = I::from_usize(root_of_unity(order, modulus))
            .expect("root of unity is not a valid usize");
        Self::with_ciphertext_root_of_unity(order, ciphertext_modulus, root_of_unity)
    }

    pub fn with_ciphertext_root_of_unity(
        order: usize,
        ciphertext_modulus: I,
        root_of_unity: I,
    ) -> Self {
        Self::with_big_ciphertext_params(
            order,
            ciphertext_modulus,
            root_of_unity,
            I::zero(),
            I::zero(),
        )
    }

    pub fn with_big_ciphertext_params(
        cyclotomic_order: usize,
        ciphertext_modulus: I,
        root_of_unity: I,
        big_ciphertext_modulus: I,
        big_root_of_unity: I,
    ) -> Self {
        Self {
            ring_dimension: get_totient(cyclotomic_order),
            cyclotomic_order,
            ciphertext_modulus,
            root_of_unity,
            big_ciphertext_modulus,
            big_root_of_unity,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DcrtElementParamsBuilder<I: IntType> {
    pub ciphertext_order: usize,
    pub modulus: Option<I>,
    pub depth: Option<usize>,
    pub bits: Option<usize>,
    pub moduli: Option<Vec<I>>,
    pub roots_of_unity: Option<Vec<I>>,
    pub big_moduli: Option<Vec<I>>,
    pub big_roots_of_unity: Option<Vec<I>>,
}

impl<I: IntType> DcrtElementParamsBuilder<I> {
    pub fn new(ciphertext_order: usize) -> Self {
        Self {
            ciphertext_order,
            modulus: None,
            depth: None,
            bits: None,
            moduli: None,
            roots_of_unity: None,
            big_moduli: None,
            big_roots_of_unity: None,
        }
    }

    pub fn build(self) -> Result<DcrtElementParams<I>> {
        match (
            self.modulus,
            self.depth,
            self.bits,
            self.moduli,
            self.roots_of_unity,
            self.big_moduli,
            self.big_roots_of_unity,
        ) {
            (Some(modulus), None, None, None, None, None, None) => {
                let mut q = previous_prime(1u64 << MAX_MODULUS_SIZE);
                let mut params = VecDeque::with_capacity(32);
                params.push_back(ElementParams::with_modulus(
                    self.ciphertext_order,
                    I::from_u64(q).expect("q is not compatible with u64"),
                ));
                let mut composite_modulus = q;
                let m = modulus
                    .to_u64()
                    .expect("modulus is not compatible with usize");
                while composite_modulus < m {
                    q = previous_prime(q - 1);
                    params.push_back(ElementParams::with_modulus(
                        self.ciphertext_order,
                        I::from_u64(q).expect("q is not compatible with u64"),
                    ));
                    composite_modulus *= q;
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: I::from_u64(composite_modulus)
                        .expect("composite_modulus is not compatible with u64"),
                })
            }
            (None, Some(depth), bits, None, None, None, None) => {
                let bits = bits.unwrap_or(MAX_MODULUS_SIZE);
                if bits > MAX_MODULUS_SIZE {
                    return Err(Error::DcrtElementParamsMismatch);
                }
                let mut q = previous_prime(1u64 << bits);
                let mut params = VecDeque::with_capacity(depth);
                params.push_back(ElementParams::with_modulus(
                    self.ciphertext_order,
                    I::from_u64(q).expect("q is not compatible with u64"),
                ));
                let mut composite_modulus = q;
                for _ in 1..depth {
                    q = previous_prime(q - 1);
                    params.push_back(ElementParams::with_modulus(
                        self.ciphertext_order,
                        I::from_u64(q).expect("q is not compatible with u64"),
                    ));
                    composite_modulus *= q;
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: I::from_u64(composite_modulus)
                        .expect("composite_modulus is not compatible with u64"),
                })
            }
            (None, None, None, Some(moduli), None, None, None) => {
                let mut params = VecDeque::with_capacity(moduli.len());
                let mut composite_modulus = I::one();
                for modulus in moduli.iter() {
                    params.push_back(ElementParams::with_modulus(self.ciphertext_order, *modulus));
                    composite_modulus *= *modulus;
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: composite_modulus,
                })
            }
            (None, None, None, Some(moduli), Some(roots_of_unity), None, None) => {
                if moduli.len() != roots_of_unity.len() {
                    return Err(Error::DcrtElementParamsMismatch);
                }
                let mut params = VecDeque::with_capacity(moduli.len());
                let mut composite_modulus = I::one();
                for (modulus, root_of_unity) in moduli.iter().zip(roots_of_unity.iter()) {
                    params.push_back(ElementParams::with_ciphertext_root_of_unity(
                        self.ciphertext_order,
                        *modulus,
                        *root_of_unity,
                    ));
                    composite_modulus *= *modulus;
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: composite_modulus,
                })
            }
            (
                None,
                None,
                None,
                Some(moduli),
                Some(roots_of_unity),
                Some(big_moduli),
                Some(big_roots_of_unity),
            ) => {
                if moduli.len() != roots_of_unity.len()
                    || moduli.len() != big_moduli.len()
                    || moduli.len() != big_roots_of_unity.len()
                {
                    return Err(Error::DcrtElementParamsMismatch);
                }

                let mut params = VecDeque::with_capacity(moduli.len());
                let mut composite_modulus = I::one();
                for ((modulus, root_of_unity), (big_modulus, big_root_of_unity)) in moduli
                    .iter()
                    .zip(roots_of_unity.iter())
                    .zip(big_moduli.iter().zip(big_roots_of_unity.iter()))
                {
                    params.push_back(ElementParams::with_big_ciphertext_params(
                        self.ciphertext_order,
                        *modulus,
                        *root_of_unity,
                        *big_modulus,
                        *big_root_of_unity,
                    ));
                    composite_modulus *= *modulus;
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: composite_modulus,
                })
            }
            _ => Err(Error::DcrtElementParamsMismatch),
        }
    }

    pub fn modulus(mut self, modulus: I) -> Self {
        self.modulus = Some(modulus);
        self
    }

    pub fn depth(mut self, depth: usize) -> Self {
        self.depth = Some(depth);
        self
    }

    pub fn bits(mut self, bits: usize) -> Self {
        self.bits = Some(bits);
        self
    }

    pub fn moduli(mut self, moduli: Vec<I>) -> Self {
        self.moduli = Some(moduli);
        self
    }

    pub fn roots_of_unity(mut self, roots_of_unity: Vec<I>) -> Self {
        self.roots_of_unity = Some(roots_of_unity);
        self
    }

    pub fn big_moduli(mut self, big_moduli: Vec<I>) -> Self {
        self.big_moduli = Some(big_moduli);
        self
    }

    pub fn big_roots_of_unity(mut self, big_roots_of_unity: Vec<I>) -> Self {
        self.big_roots_of_unity = Some(big_roots_of_unity);
        self
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Display, Serialize, Deserialize)]
#[display("DcrtElementParams {{ params: [{}] }}", params)]
#[serde(bound = "I: IntType")]
pub struct DcrtElementParams<I: IntType> {
    params: VecDeque<ElementParams<I>>,
    ciphertext_composite_modulus: I,
}

impl<I: IntType> Index<usize> for DcrtElementParams<I> {
    type Output = ElementParams<I>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.params[index]
    }
}

impl<I: IntType> IndexMut<usize> for DcrtElementParams<I> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.params[index]
    }
}

impl<I: IntType> DcrtElementParams<I> {
    pub fn params(&self) -> &VecDeque<ElementParams<I>> {
        &self.params
    }

    pub fn pop_front(&mut self) {
        if let Some(elem) = self.params.pop_front() {
            self.ciphertext_composite_modulus /= elem.ciphertext_modulus;
        }
    }

    pub fn pop_back(&mut self) {
        if let Some(elem) = self.params.pop_back() {
            self.ciphertext_composite_modulus /= elem.ciphertext_modulus;
        }
    }
}
