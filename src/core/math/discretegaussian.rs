use crate::core::math::VecMod;
use crate::core::utils::find_in_vector;
use crypto_bigint::modular::{MontyParams, SafeGcdInverter};
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};
use rand::distr::Open01;
use rand::prelude::*;
use rand_distr::{Distribution, Normal, StandardNormal};
use std::f64::consts::E;
use std::marker::PhantomData;

pub const KARNEY_THRESHOLD: f64 = 300.0;

#[derive(Debug)]
pub struct DiscreteGaussian {
    normal: Normal<f64>,
    rng: StdRng,
    values: Vec<f64>,
    peikert: bool,
}

impl Default for DiscreteGaussian {
    fn default() -> Self {
        Self {
            normal: Normal::new(0.0, 1.0).unwrap(),
            rng: StdRng::from_os_rng(),
            values: Vec::new(),
            peikert: false,
        }
    }
}

impl DiscreteGaussian {
    /// Calculates the unnormalized Gaussian PDF for a discrete point x
    pub fn unnormalized_gaussian_probability_density_function(
        mean: f64,
        sigma: f64,
        x: i32,
    ) -> f64 {
        E.powf(-(x as f64 - mean).powi(2) / (2.0 * sigma * sigma))
    }

    /// Optimized version where sigmaFactor = -1/(2*sigma^2)
    pub fn unnormalized_gaussian_probability_density_function_optimized(
        mean: f64,
        sigma_factor: f64,
        x: i32,
    ) -> f64 {
        E.powf(sigma_factor * (x as f64 - mean).powi(2))
    }

    fn algorithm_b<R: Rng>(rng: &mut R, k: i32, x: f64) -> bool {
        let mut y = x as f32;
        let m = (2 * k + 2) as f32;
        let kk = k as f32;
        let xx = x as f32;
        let mut n = 0;

        loop {
            let z: f32 = StandardNormal.sample(rng);
            if z > y {
                break;
            } else if z < y {
                let r: f32 = StandardNormal.sample(rng);
                let r_temp: f32 = (2.0 * kk + xx) / m;
                if r > r_temp {
                    break;
                } else if r < r_temp {
                    y = z;
                } else {
                    return Self::algorithm_b_double(rng, k, x);
                }
            } else {
                return Self::algorithm_b_double(rng, k, x);
            }

            n += 1;
        }
        n & 1 == 0
    }

    fn algorithm_b_double<R: Rng>(rng: &mut R, k: i32, x: f64) -> bool {
        let mut y = x;
        let kk = k as f64;
        let mut n = 0;
        let m = (2 * k + 2) as f64;

        loop {
            let z: f64 = StandardNormal.sample(rng);
            if !(z < y) {
                break;
            }
            let r: f64 = StandardNormal.sample(rng);
            if !(r < (2.0 * kk + x) / m) {
                break;
            }

            y = z;
            n += 1;
        }

        n & 1 == 0
    }

    fn algorithm_g<R: Rng>(rng: &mut R) -> i32 {
        let mut n = 0;
        while Self::algorithm_h(rng) {
            n += 1;
        }
        n
    }

    fn algorithm_h<R: Rng>(rng: &mut R) -> bool {
        let mut h_a: f32 = StandardNormal.sample(rng);
        let mut h_b;

        if h_a > 0.5 {
            true
        } else if h_a < 0.5 {
            loop {
                h_b = StandardNormal.sample(rng);
                if h_b > h_a {
                    return false;
                } else if h_b < h_a {
                    h_a = StandardNormal.sample(rng);
                } else {
                    return Self::algorithm_h_double(rng);
                }
                if h_a > h_b {
                    return true;
                } else if h_a == h_b {
                    return Self::algorithm_h_double(rng);
                }
            }
        } else {
            // Equal
            Self::algorithm_h_double(rng)
        }
    }

    fn algorithm_h_double<R: Rng>(rng: &mut R) -> bool {
        let mut h_a: f64 = StandardNormal.sample(rng);
        let mut h_b;

        if !(h_a < 0.5) {
            return true;
        }
        loop {
            h_b = StandardNormal.sample(rng);
            if !(h_b < h_a) {
                return false;
            } else {
                h_a = StandardNormal.sample(rng);
            }
            if !(h_a < h_b) {
                return true;
            }
        }
    }

    fn algorithm_p<R: Rng>(rng: &mut R, mut n: i32) -> bool {
        while n != 0 && Self::algorithm_h(rng) {
            n -= 1;
        }
        n < 0
    }

    pub fn new(std_dev: f64) -> Result<Self, rand_distr::NormalError> {
        let normal = Normal::new(0.0, std_dev)?;
        Ok(Self {
            normal,
            rng: StdRng::from_os_rng(),
            values: Vec::new(),
            peikert: false,
        })
    }

    pub fn gen_i32(&mut self) -> i32 {
        let seed: f64 = self.rng.sample(Open01);
        let seed = seed - 0.5;
        let tmp = seed.abs() - self.normal.mean() / 2.0;
        if tmp <= 0.0 {
            return 0;
        }
        (find_in_vector(&self.values, tmp) * (if seed > 0.0 { 1 } else { -1 })) as i32
    }

    pub fn gen_i32_with_params(mean: f64, std_dev: f64, ring_dimension: usize) -> i32 {
        const LIMIT: usize = 10_000;

        let mut rng = StdRng::from_os_rng();
        let t = ring_dimension.ilog2() as f64 * std_dev;
        let uniform_int = Normal::<f64>::new((mean - t).floor(), (mean + t).ceil()).unwrap();
        let sigma_factor = 1.0 / (-2.0 * std_dev * std_dev);
        let mut count = 0;
        let mut x = 0;
        let mut success = false;

        while !success {
            x = uniform_int.sample(&mut rng) as i32;
            let dice: f64 = rng.sample(StandardNormal);
            success = dice
                <= Self::unnormalized_gaussian_probability_density_function_optimized(
                    mean,
                    sigma_factor,
                    x,
                );
            count += 1;

            if count > LIMIT {
                panic!("Failed to generate a valid sample after {} attempts", LIMIT);
            }
        }
        x
    }

    pub fn gen_i32_karney(mean: f64, std_dev: f64) -> i32 {
        let uniform_j = Normal::<f64>::new(0.0, std_dev.ceil() - 1.0).expect("");
        let mut rng = StdRng::from_os_rng();

        loop {
            let k = Self::algorithm_g(&mut rng);

            if !Self::algorithm_p(&mut rng, k) {
                continue;
            }

            let s: f64 = rng.sample(StandardNormal);
            let mut s = s as i64;
            if s == 0 {
                s = -1;
            }

            let di0 = std_dev * (k as f64) + (s as f64) * mean;
            let i0 = di0.ceil() as i64;
            let x0 = (i0 as f64 - di0) / std_dev;
            let j = uniform_j.sample(&mut rng) as i64;

            let x = x0 + j as f64 / std_dev;

            if !(x < 1.0) || (x == 0.0 && s < 0 && k == 0) {
                continue;
            }

            let mut h = k + 1;
            while h != 0 && Self::algorithm_b(&mut rng, k, x) {
                h -= 1;
            }

            if !(h < 0) {
                continue;
            }

            return (s * (i0 + j)) as i32;
        }
    }

    pub fn gen_i64_vec(&mut self, length: usize) -> Vec<i64> {
        let mut result = Vec::with_capacity(length);
        if !self.peikert {
            for _ in 0..length {
                result.push(Self::gen_i32_karney(0.0, self.normal.mean()) as i64);
            }
            return result;
        }

        for _ in 0..length {
            let seed: f64 = self.rng.sample(Open01);
            let seed = seed - 0.5;
            let tmp = seed.abs() - self.normal.mean() / 2.0;
            let mut val = 0;
            if tmp > 0.0 {
                val = find_in_vector(&self.values, tmp) * if seed > 0.0 { 1 } else { -1 };
            }
            result.push(val as i64);
        }

        result
    }

    pub fn gen_uint<const LIMBS: usize>(&mut self, modulus: &Odd<Uint<LIMBS>>) -> Uint<LIMBS> {
        let seed: f64 = self.rng.sample(Open01);
        let seed = seed - 0.5;
        let tmp = seed.abs() - self.normal.mean() / 2.0;
        if tmp <= 0.0 {
            return Uint::ZERO;
        }
        let val = find_in_vector(&self.values, tmp) * (if seed > 0.0 { 1 } else { -1 });
        if val < 0 {
            return **modulus - Uint::from(val.abs() as u64);
        }
        Uint::from(val as u64)
    }

    pub fn gen_uint_with_params<const LIMBS: usize>(
        mean: f64,
        std_dev: f64,
        ring_dimension: usize,
        modulus: &Odd<Uint<LIMBS>>,
    ) -> Uint<LIMBS> {
        let mut rng = StdRng::from_os_rng();
        let t = ring_dimension.ilog2() as f64 * std_dev;
        let uniform_int = Normal::<f64>::new((mean - t).floor(), (mean + t).ceil()).unwrap();

        let mut x = rng.sample(uniform_int) as i32;
        let mut not_finished = rng.sample::<f64, _>(Open01)
            > Self::unnormalized_gaussian_probability_density_function(mean, std_dev, x);
        while !not_finished {
            x = rng.sample(uniform_int) as i32;
            not_finished = rng.sample::<f64, _>(Open01)
                > Self::unnormalized_gaussian_probability_density_function(mean, std_dev, x);
        }

        if x < 0 {
            return **modulus - Uint::from(x.abs() as u64);
        }
        Uint::from(x as u64)
    }

    pub fn gen_vec_mod<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>(
        &mut self,
        length: usize,
        modulus: &Odd<Uint<LIMBS>>,
    ) -> VecMod<LIMBS, WIDE_LIMBS>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
    {
        VecMod {
            values: self
                .gen_i64_vec(length)
                .into_iter()
                .map(|i| {
                    if i < 0 {
                        **modulus - Uint::from(i.abs() as u64)
                    } else {
                        Uint::from(i as u64)
                    }
                })
                .collect(),
            params: MontyParams::new(*modulus),
            _marker: PhantomData,
        }
    }

    pub fn get_std_dev(&self) -> f64 {
        self.normal.std_dev()
    }

    pub fn set_std_dev(&mut self, std_dev: f64) {
        if std_dev.log2() > 59.0 {
            panic!("Standard deviation too large");
        }

        self.normal =
            Normal::new(self.normal.mean(), std_dev).expect("Failed to create normal distribution");
        self.peikert = std_dev < KARNEY_THRESHOLD;
        self.initialize();
    }

    fn initialize(&mut self) {
        // usually the bound of m_std * M is used, where M = 12 .. 40
        // we use M = std::sqrt(-2. * std::log(5e-32)) = 12.0061 here,
        // which corresponds to the probability of roughly 2^(-100)
        const M: f64 = 12.00610553538285;
        let fin = (self.normal.std_dev() * M).ceil() as usize;
        self.values.clear();
        self.values.reserve(fin);
        let variance = 2.0 * self.normal.std_dev() * self.normal.std_dev();
        let mut cusum = 0.0;

        for x in 1..=fin {
            cusum += (-((x * x) as f64 / variance)).exp();
            self.values.push(cusum);
        }

        let mean = 1.0 / (2.0 * cusum + 1.0);
        for x in 0..fin {
            self.values[x] *= mean;
        }

        self.normal =
            Normal::new(mean, self.get_std_dev()).expect("Failed to create normal distribution");
    }
}
