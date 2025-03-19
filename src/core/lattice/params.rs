use crate::constants::{DistributionType, MAX_MODULUS_SIZE, SecurityLevel};
use crate::core::utils::{get_totient, previous_prime, root_of_unity};
use crate::error::Error;
use crypto_bigint::{Odd, U64};
use derive_more::Display;
use serde::{Deserialize, Serialize};
use std::cell::{LazyCell, OnceCell};
use std::collections::{HashMap, VecDeque};
use std::ops::{Index, IndexMut};
use std::sync::LazyLock;
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
    pub ring_dimension: usize,
    /// The cyclotomic order
    pub cyclotomic_order: usize,
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
    pub fn with_modulus_bits(order: usize, bits: usize) -> Self {
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

    pub fn with_modulus(order: usize, ciphertext_modulus: Odd<U64>) -> Self {
        let root_of_unity = root_of_unity(order, ciphertext_modulus);
        Self::with_ciphertext_root_of_unity(order, ciphertext_modulus, root_of_unity)
    }

    pub fn with_ciphertext_root_of_unity(
        order: usize,
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
        cyclotomic_order: usize,
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
    pub ciphertext_order: usize,
    pub modulus: Option<Odd<U64>>,
    pub depth: Option<usize>,
    pub bits: Option<usize>,
    pub moduli: Option<Vec<Odd<U64>>>,
    pub roots_of_unity: Option<Vec<U64>>,
    pub big_moduli: Option<Vec<Odd<U64>>>,
    pub big_roots_of_unity: Option<Vec<U64>>,
}

impl DcrtElementParamsBuilder {
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

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Display, Serialize, Deserialize)]
#[display(
    "LatticeParams {{ distribution_type: {distribution_type}, ring_dimension: {ring_dimension}, min_security_level: {min_security_level}, max_log_q: {max_log_q} }}"
)]
pub struct LatticeParams {
    pub distribution_type: DistributionType,
    pub ring_dimension: usize,
    pub min_security_level: SecurityLevel,
    pub max_log_q: usize,
}

impl LatticeParams {
    pub fn find_max_q(
        distribution_type: DistributionType,
        security_level: SecurityLevel,
        ring_dimension: usize,
    ) -> usize {
        let dist = distribution_type as usize;
        let sec = security_level as usize;
        BY_RING[dist][sec]
            .get(&ring_dimension)
            .map(|l| l.max_log_q)
            .unwrap_or_default()
    }

    pub fn find_ring_dimension(
        distribution_type: DistributionType,
        security_level: SecurityLevel,
        current_log_q: usize,
    ) -> usize {
        let dist = distribution_type as usize;
        let sec = security_level as usize;
        let mut prev = 0;
        let mut n = 0;
        for (&log_q, &lattice) in BY_LOG_Q[dist][sec].iter() {
            if current_log_q <= log_q && current_log_q > prev {
                return lattice.ring_dimension;
            }
            prev = log_q;
            n = lattice.ring_dimension;
        }
        n * 2
    }
}

static BY_RING: LazyLock<
    [[HashMap<usize, &'static LatticeParams>; SecurityLevel::NUM_VALUES];
        DistributionType::NUM_VALUES],
> = LazyLock::new(|| {
    let mut map = [
        [
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
        ],
        [
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
        ],
        [
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
        ],
    ];
    for p in LATTICE_PARAMS.iter() {
        map[p.distribution_type as usize][p.min_security_level as usize]
            .insert(p.ring_dimension, p);
    }
    map
});

static BY_LOG_Q: LazyLock<
    [[HashMap<usize, &'static LatticeParams>; SecurityLevel::NUM_VALUES];
        DistributionType::NUM_VALUES],
> = LazyLock::new(|| {
    let mut map = [
        [
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
        ],
        [
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
        ],
        [
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
            HashMap::with_capacity(LATTICE_PARAMS.len()),
        ],
    ];
    for p in LATTICE_PARAMS.iter() {
        map[p.distribution_type as usize][p.min_security_level as usize].insert(p.max_log_q, p);
    }
    map
});

static LATTICE_PARAMS: LazyLock<Vec<LatticeParams>> = LazyLock::new(|| {
    vec![
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 29,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 21,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 16,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 56,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 39,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 31,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 111,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 77,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 60,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 220,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 154,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 120,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 440,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 307,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 239,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 880,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 612,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 478,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 29,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 21,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 16,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 56,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 39,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 31,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 111,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 77,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 60,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 220,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 154,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 120,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 440,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 307,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 239,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 883,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 613,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 478,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 1749,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 1201,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 931,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 3525,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 2413,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 1868,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 27,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 19,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 14,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 54,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 37,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 29,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 109,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 75,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 58,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 218,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 152,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 118,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 438,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 305,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 237,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 881,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 611,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 476,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 1747,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 1199,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 929,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd128Classic,
            max_log_q: 3523,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd192Classic,
            max_log_q: 2411,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd256Classic,
            max_log_q: 1866,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 27,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 19,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 15,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 53,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 37,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 29,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 103,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 72,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 56,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 206,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 143,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 111,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 413,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 286,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 222,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 829,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 573,
        },
        LatticeParams {
            distribution_type: DistributionType::Uniform,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 445,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 27,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 19,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 15,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 53,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 37,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 29,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 103,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 72,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 56,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 206,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 143,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 111,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 413,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 286,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 222,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 829,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 573,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 445,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 1665,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 1147,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 890,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 3351,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 2304,
        },
        LatticeParams {
            distribution_type: DistributionType::Error,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 1786,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 25,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 17,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 1024,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 13,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 51,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 35,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 2048,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 27,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 101,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 70,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 4096,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 54,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 202,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 141,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 8192,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 109,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 411,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 284,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 16384,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 220,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 827,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 571,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 32768,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 443,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 1663,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 1145,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 65536,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 888,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd128Quantum,
            max_log_q: 3348,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd192Quantum,
            max_log_q: 2301,
        },
        LatticeParams {
            distribution_type: DistributionType::Ternary,
            ring_dimension: 131072,
            min_security_level: SecurityLevel::HeStd256Quantum,
            max_log_q: 1784,
        },
    ]
});
