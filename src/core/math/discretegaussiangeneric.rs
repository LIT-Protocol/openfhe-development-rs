use crate::core::math::{BaseSampler, Sampler, SamplerCombiner};
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::{cmp, ptr};

const PRECISION: usize = 53;
const BERNOULLI_FLIPS: usize = 23;

pub struct DiscreteGaussianGeneric {
    pub(crate) base_samplers: Vec<Arc<Mutex<BaseSampler>>>,
    pub(crate) wide_sampler: Arc<Mutex<dyn Sampler>>,
    pub(crate) combiners: [Arc<Mutex<dyn Sampler>>; 4],
    pub(crate) wide_variance: f64,
    pub(crate) sampler_variance: f64,
    pub(crate) x: f64,
    pub(crate) c: f64,
    pub(crate) ci: f64,
    pub(crate) k: usize,
    pub(crate) log_base: usize,
    pub(crate) mask: u64,
}

impl DiscreteGaussianGeneric {
    pub fn new(
        samplers: &[Arc<Mutex<BaseSampler>>],
        std_dev: f64,
        log_base: usize,
        n: f64,
    ) -> Self {
        let base_variance = std_dev * std_dev;
        let base_samplers = samplers.to_vec();

        let mut wide_variance = base_variance;
        let mut x1;
        let mut x2;
        let mut combiners = [
            MaybeUninit::<Arc<Mutex<dyn Sampler>>>::uninit(),
            MaybeUninit::<Arc<Mutex<dyn Sampler>>>::uninit(),
            MaybeUninit::<Arc<Mutex<dyn Sampler>>>::uninit(),
            MaybeUninit::<Arc<Mutex<dyn Sampler>>>::uninit(),
        ];
        let mut wide_sampler: Arc<Mutex<dyn Sampler>> = base_samplers[0].clone();
        let t = 2.0 * n * n;
        for i in 1..4 {
            x1 = (wide_variance / t).sqrt().floor() as i64;
            x2 = cmp::max(x1 - 1, 1);
            wide_sampler = Arc::new(Mutex::new(SamplerCombiner {
                sampler: wide_sampler.clone(),
                x1,
                x2,
            }));
            combiners[i - 1].write(wide_sampler.clone());
            wide_variance *= (x1 * x1 + x2 * x2) as f64;
        }
        let k = (((PRECISION - BERNOULLI_FLIPS) as f64) / (log_base as f64)).ceil() as usize;
        let mask = (1u64 << log_base) - 1;
        let mut sampler_variance = 1f64;
        let t = 1.0 / ((1u64 << (2 * log_base)) as f64);
        let mut s = 1f64;
        for _ in 1..k {
            s *= t;
            sampler_variance += s;
        }
        sampler_variance *= base_variance;
        Self {
            base_samplers,
            wide_sampler,
            combiners: unsafe {
                [
                    combiners[0].assume_init_read(),
                    combiners[1].assume_init_read(),
                    combiners[2].assume_init_read(),
                    combiners[3].assume_init_read(),
                ]
            },
            wide_variance,
            sampler_variance,
            x: 0.0,
            c: 0.0,
            ci: 0.0,
            k: 0,
            log_base,
            mask,
        }
    }

    pub fn random_i64(&mut self) -> i64 {
        self.base_samplers[0].lock().unwrap().random_i64()
    }

    pub fn random_i64_with_params(&mut self, mean: f64, std_dev: f64) -> i64 {
        let variance = std_dev * std_dev;
        self.x = self.wide_sampler.lock().unwrap().random_i64() as f64;
        self.c = mean + self.x * ((variance - self.sampler_variance) / self.wide_variance).sqrt();
        self.ci = self.c.floor();
        self.c -= self.ci;

        (self.ci as i64) + self.flip_and_round(self.c)
    }

    fn flip_and_round(&mut self, center: f64) -> i64 {
        let c = (center * ((1u64 << PRECISION) as f64)) as i64;
        let base_c = c >> BERNOULLI_FLIPS;
        let mut bit;

        for i in (0..BERNOULLI_FLIPS).rev() {
            bit = self.base_samplers[0].lock().unwrap().random_bit();
            let t = extract_bit(c, i);
            if bit > t {
                return self.sample_c(base_c);
            }
            if bit < t {
                return self.sample_c(base_c + 1);
            }
        }
        self.sample_c(base_c + 1)
    }

    fn sample_c(&mut self, center: i64) -> i64 {
        let mut c = center;
        let mask = self.mask as i64;
        for _ in 0..self.k {
            let index = (mask & c) as usize;
            let mut sample = self.base_samplers[index].lock().unwrap().random_i64();
            if c < 0 {
                sample -= 1;
            }
            for _ in 0..self.log_base {
                c >>= 1;
            }
            c += sample;
        }
        c
    }
}

fn extract_bit(number: i64, n: usize) -> u16 {
    ((number >> n) & 1) as u16
}
