use crate::constants::MAX_MODULUS_SIZE;
use crate::core::utils::{get_totient, previous_prime, root_of_unity};
use crate::error::Error;
use crypto_bigint::{Odd, U64};
use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::ops::{Index, IndexMut};
use subtle::CtOption;

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
pub struct ElementParams {
    /// The ring dimension
    pub ring_dimension: U64,
    /// The cyclotomic order
    pub cyclotomic_order: U64,
    /// The ciphertext modulus
    pub ciphertext_modulus: Odd<U64>,
    /// The ciphertext modulus root of unity
    pub root_of_unity: U64,
    /// The big ciphertext modulus used for bit-packing operations
    pub big_ciphertext_modulus: Odd<U64>,
    /// The big ciphertext modulus root of unity
    pub big_root_of_unity: U64,
}

impl ElementParams {
    pub fn with_modulus_bits(order: U64, bits: usize) -> Self {
        if bits > MAX_MODULUS_SIZE {
            panic!(
                "Requested bit length {} exceeds maximum allowed length {}",
                bits, MAX_MODULUS_SIZE
            );
        }

        let modulus: U64 = crypto_primes::generate_prime(bits as u32);
        Self::with_modulus(
            order,
            CtOption::from(modulus.to_odd()).expect("Invalid modulus"),
        )
    }

    pub fn with_modulus(order: U64, ciphertext_modulus: Odd<U64>) -> Self {
        let root_of_unity = root_of_unity(order, ciphertext_modulus);
        Self::with_ciphertext_root_of_unity(order, ciphertext_modulus, root_of_unity)
    }

    pub fn with_ciphertext_root_of_unity(
        order: U64,
        ciphertext_modulus: Odd<U64>,
        root_of_unity: U64,
    ) -> Self {
        Self::with_big_ciphertext_params(
            order,
            ciphertext_modulus,
            root_of_unity,
            Odd::new(U64::ONE).expect("One is odd"),
            U64::ZERO,
        )
    }

    pub fn with_big_ciphertext_params(
        cyclotomic_order: U64,
        ciphertext_modulus: Odd<U64>,
        root_of_unity: U64,
        big_ciphertext_modulus: Odd<U64>,
        big_root_of_unity: U64,
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
pub struct DcrtElementParamsBuilder {
    pub ciphertext_order: U64,
    pub modulus: Option<Odd<U64>>,
    pub depth: Option<usize>,
    pub bits: Option<usize>,
    pub moduli: Option<Vec<Odd<U64>>>,
    pub roots_of_unity: Option<Vec<U64>>,
    pub big_moduli: Option<Vec<Odd<U64>>>,
    pub big_roots_of_unity: Option<Vec<U64>>,
}

impl DcrtElementParamsBuilder {
    pub fn new(ciphertext_order: U64) -> Self {
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

    pub fn build(self) -> crate::error::Result<DcrtElementParams> {
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
                let mut q: U64 = crypto_primes::generate_prime(MAX_MODULUS_SIZE as u32);
                let mut params = VecDeque::with_capacity(32);
                params.push_back(ElementParams::with_modulus(
                    self.ciphertext_order,
                    CtOption::from(q.to_odd()).expect("modulus is not odd"),
                ));
                let mut composite_modulus = q;
                while composite_modulus < modulus {
                    q = previous_prime(q, self.ciphertext_order);
                    params.push_back(ElementParams::with_modulus(
                        self.ciphertext_order,
                        CtOption::from(q.to_odd()).expect("modulus is not odd"),
                    ));
                    composite_modulus *= q;
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: composite_modulus,
                })
            }
            (None, Some(depth), bits, None, None, None, None) => {
                let bits = bits.unwrap_or(MAX_MODULUS_SIZE);
                if bits > MAX_MODULUS_SIZE {
                    return Err(Error::DcrtElementParamsMismatch);
                }
                let mut q: U64 = crypto_primes::generate_prime(MAX_MODULUS_SIZE as u32);
                let mut params = VecDeque::with_capacity(depth);
                params.push_back(ElementParams::with_modulus(
                    self.ciphertext_order,
                    CtOption::from(q.to_odd()).expect("modulus is not odd"),
                ));
                let mut composite_modulus = q;
                for _ in 1..depth {
                    q = previous_prime(q, self.ciphertext_order);
                    params.push_back(ElementParams::with_modulus(
                        self.ciphertext_order,
                        CtOption::from(q.to_odd()).expect("modulus is not odd"),
                    ));
                    composite_modulus *= q;
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: composite_modulus,
                })
            }
            (None, None, None, Some(moduli), None, None, None) => {
                let mut params = VecDeque::with_capacity(moduli.len());
                let mut composite_modulus = U64::ONE;
                for modulus in moduli.iter() {
                    params.push_back(ElementParams::with_modulus(self.ciphertext_order, *modulus));
                    composite_modulus *= modulus.get();
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
                let mut composite_modulus = U64::ONE;
                for (modulus, root_of_unity) in moduli.iter().zip(roots_of_unity.iter()) {
                    params.push_back(ElementParams::with_ciphertext_root_of_unity(
                        self.ciphertext_order,
                        *modulus,
                        *root_of_unity,
                    ));
                    composite_modulus *= modulus.get();
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
                let mut composite_modulus = U64::ONE;
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
                    composite_modulus *= modulus.get();
                }
                Ok(DcrtElementParams {
                    params,
                    ciphertext_composite_modulus: composite_modulus,
                })
            }
            _ => Err(Error::DcrtElementParamsMismatch),
        }
    }

    pub fn modulus(mut self, modulus: Odd<U64>) -> Self {
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

    pub fn moduli(mut self, moduli: Vec<Odd<U64>>) -> Self {
        self.moduli = Some(moduli);
        self
    }

    pub fn roots_of_unity(mut self, roots_of_unity: Vec<U64>) -> Self {
        self.roots_of_unity = Some(roots_of_unity);
        self
    }

    pub fn big_moduli(mut self, big_moduli: Vec<Odd<U64>>) -> Self {
        self.big_moduli = Some(big_moduli);
        self
    }

    pub fn big_roots_of_unity(mut self, big_roots_of_unity: Vec<U64>) -> Self {
        self.big_roots_of_unity = Some(big_roots_of_unity);
        self
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Display, Serialize, Deserialize)]
#[display(
    "DcrtElementParams {{ params: [{:?}], ciphertext_composite_modulus: {} }}",
    params,
    ciphertext_composite_modulus
)]
pub struct DcrtElementParams {
    params: VecDeque<ElementParams>,
    ciphertext_composite_modulus: U64,
}

impl Index<usize> for DcrtElementParams {
    type Output = ElementParams;

    fn index(&self, index: usize) -> &Self::Output {
        &self.params[index]
    }
}

impl IndexMut<usize> for DcrtElementParams {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.params[index]
    }
}

impl DcrtElementParams {
    pub fn params(&self) -> &VecDeque<ElementParams> {
        &self.params
    }

    pub fn pop_front(&mut self) {
        if let Some(elem) = self.params.pop_front() {
            self.ciphertext_composite_modulus /=
                CtOption::from(elem.ciphertext_modulus.to_nz()).expect("Invalid modulus");
        }
    }

    pub fn pop_back(&mut self) {
        if let Some(elem) = self.params.pop_back() {
            self.ciphertext_composite_modulus /=
                CtOption::from(elem.ciphertext_modulus.to_nz()).expect("Invalid modulus");
        }
    }
}
