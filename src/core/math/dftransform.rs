use crate::error::Result;
use num::complex::Complex;
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
};

static ROOT_OF_UNITY_TABLE: OnceLock<Arc<RwLock<Vec<Complex<f64>>>>> = OnceLock::new();
static PRECOMPUTED_VALUES_TABLE: OnceLock<Arc<RwLock<HashMap<usize, PrecomputedValues>>>> =
    OnceLock::new();

pub fn reset() -> Result<()> {
    ROOT_OF_UNITY_TABLE
        .get_or_init(Default::default)
        .write()?
        .clear();
    Ok(())
}

pub fn initialize(m: usize, nh: usize) -> Result<()> {
    let mut table = PRECOMPUTED_VALUES_TABLE
        .get_or_init(Default::default)
        .write()?;
    table.entry(m).or_insert(PrecomputedValues::new(m, nh));
    Ok(())
}

pub fn precompute_table(s: usize) -> Result<()> {
    reset()?;

    let mut table = ROOT_OF_UNITY_TABLE.get_or_init(Default::default).write()?;
    for j in 0..s {
        let theta = -2.0 * std::f64::consts::PI * (j as f64) / (s as f64);
        table.push(Complex::from_polar(1.0, theta));
    }
    Ok(())
}

pub fn fft_forward_transform(a: &[Complex<f64>]) -> Result<Vec<Complex<f64>>> {
    static TABLES: OnceLock<RwLock<Tables>> = OnceLock::new();

    let m = a.len();
    let mut b = a.to_vec();
    let l = m.ilog2() as usize;

    {
        let mut tables = TABLES.get_or_init(Default::default).write()?;

        if m != tables.cached_m[l] {
            let half_m = m / 2;
            tables.cached_m[l] = m;
            tables.sin_table[l].resize(half_m, 0.0);
            tables.cos_table[l].resize(half_m, 0.0);
            for i in 0..half_m {
                let angle = 2.0 * std::f64::consts::PI * (i as f64) / (m as f64);
                tables.cos_table[l][i] = f64::cos(angle);
                tables.sin_table[l][i] = f64::sin(angle);
            }
        }
    }

    // bit-reversed addressing permutation
    for i in 0..m {
        let j = i.reverse_bits() >> (64 - l);
        if i < j {
            b.swap(i, j);
        }
    }

    // Cooley-Tukey decimation-in-time radix-2 FFT
    let table = TABLES.get_or_init(Default::default).read()?;
    let mut size = 2;
    while size <= m {
        let half_size = size / 2;
        let table_step = m / size;

        for i in (0..m).step_by(size) {
            let mut k = 0;
            for j in i..(i + half_size) {
                let tpre = b[j + half_size].re * table.cos_table[l][k]
                    + b[j + half_size].im * table.sin_table[l][k];
                let tpim = -b[j + half_size].re * table.sin_table[l][k]
                    + b[j + half_size].im * table.cos_table[l][k];

                b[j + half_size].re = b[j].re - tpre;
                b[j + half_size].im = b[j].im - tpim;
                b[j].re += tpre;
                b[j].im += tpim;

                k += table_step;
            }
        }

        if size == m {
            break;
        }

        size *= 2;
    }

    Ok(b)
}

/// Keep values precomputed for every cyclotomic order value
pub struct PrecomputedValues {
    // cyclotomic order
    m: usize,
    nh: usize,
    rotation_group_indices: Vec<usize>,
    ksi_powers: Vec<Complex<f64>>,
}

impl PrecomputedValues {
    pub fn new(m: usize, nh: usize) -> Self {
        let mut rotation_group_indices = Vec::with_capacity(nh);
        let mut five_powers = 1;
        for _ in 0..nh {
            rotation_group_indices.push(five_powers);
            five_powers = (five_powers * 5) % m;
        }

        let mut ksi_powers = Vec::with_capacity(m + 1);
        for i in 0..m {
            let angle = 2.0 * std::f64::consts::PI * (i as f64) / (m as f64);
            ksi_powers.push(Complex::new(f64::cos(angle), f64::sin(angle)));
        }
        let first = ksi_powers[0];
        ksi_powers.push(first);
        Self {
            m,
            nh,
            rotation_group_indices,
            ksi_powers,
        }
    }
}

struct Tables {
    logm_max: usize,
    cached_m: Vec<usize>,
    cos_table: Vec<Vec<f64>>,
    sin_table: Vec<Vec<f64>>,
}

impl Default for Tables {
    fn default() -> Self {
        Self {
            logm_max: Self::LOGM_MAX,
            cached_m: vec![0; Self::LOGM_MAX + 1],
            cos_table: vec![Vec::new(); Self::LOGM_MAX + 1],
            sin_table: vec![Vec::new(); Self::LOGM_MAX + 1],
        }
    }
}

impl Tables {
    pub const LOGM_MAX: usize = 18; // 2^18 = 262144
}
