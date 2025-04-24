use crate::core::math::Sampler;
use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SamplerCombiner {
    pub sampler: Arc<Mutex<dyn Sampler>>,
    pub x1: i64,
    pub x2: i64,
}

impl Sampler for SamplerCombiner {
    fn random_i64(&mut self) -> i64 {
        self.random_i64()
    }

    fn random_bit(&mut self) -> u16 {
        self.sampler.lock().unwrap().random_bit()
    }
}

impl Debug for SamplerCombiner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SamplerCombiner")
            .field("sampler", &"")
            .field("x1", &self.x1)
            .field("x2", &self.x2)
            .finish()
    }
}

impl SamplerCombiner {
    pub fn random_i64(&mut self) -> i64 {
        let mut s = self.sampler.lock().unwrap();
        self.x1 * s.random_i64() + self.x2 * s.random_i64()
    }
}
