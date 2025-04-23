use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Debug)]
pub struct BitGenerator {
    sequence: u32,
    counter: u32,
}

impl Default for BitGenerator {
    fn default() -> Self {
        BitGenerator {
            sequence: StdRng::from_os_rng().random::<u32>(),
            counter: 0,
        }
    }
}

impl BitGenerator {
    pub fn generate(&mut self) -> u16 {
        if self.counter == 0 {
            self.sequence = StdRng::from_os_rng().random::<u32>();
            self.counter = 32;
        }
        self.counter -= 1;
        ((self.sequence >> self.counter) & 1) as u16
    }
}
