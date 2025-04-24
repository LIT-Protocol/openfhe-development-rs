use super::BitGenerator;
use crate::constants::BaseSamplerType;
use crate::core::utils::find_in_vector;
use rand::distr::Open01;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::f64::consts::E;

pub trait Sampler {
    fn random_i64(&mut self) -> i64;
    fn random_bit(&mut self) -> u16;
}

#[derive(Debug)]
pub struct BaseSampler {
    b_a: f64,
    mean: f64,
    std_dev: f64,
    bit_generator: BitGenerator,
    base_sampler_type: BaseSamplerType,
    fin: usize,
    ddg_tree: Vec<Vec<i16>>,
    hamming_weights: Vec<u32>,
    matrix_size: usize,
    first_non_zero: isize,
    end_index: isize,
    values: Vec<f64>,
}

impl Sampler for BaseSampler {
    fn random_i64(&mut self) -> i64 {
        self.random_i64()
    }

    fn random_bit(&mut self) -> u16 {
        self.random_bit()
    }
}

impl BaseSampler {
    pub fn new(
        mean: f64,
        std_dev: f64,
        bg: BitGenerator,
        base_sampler_type: BaseSamplerType,
    ) -> Self {
        const ACC: f64 = 1e-17;
        let mut sampler = BaseSampler {
            b_a: 0.0,
            mean: if mean >= 0.0 {
                mean.floor()
            } else {
                mean.ceil()
            },
            std_dev,
            bit_generator: bg,
            base_sampler_type,
            fin: (std_dev * (-2.0 * ACC.ln()).sqrt()).ceil() as usize,
            ddg_tree: vec![],
            hamming_weights: vec![],
            matrix_size: 0,
            first_non_zero: -1,
            end_index: -1,
            values: vec![],
        };
        let mean = mean - sampler.mean * 1.0;
        if base_sampler_type == BaseSamplerType::Peikert {
            sampler.initialize(mean);
        } else {
            sampler.gen_prob_matrix(mean, std_dev);
        }
        sampler
    }

    pub fn random_i64(&mut self) -> i64 {
        match self.base_sampler_type {
            BaseSamplerType::KnuthYao => self.gen_i64_knuth_yao(),
            BaseSamplerType::Peikert => self.gen_i64_peikert(),
        }
    }

    pub fn random_bit(&mut self) -> u16 {
        self.bit_generator.generate()
    }

    fn gen_i64_knuth_yao(&mut self) -> i64 {
        let mut ans = -1;
        let mut hit = false;

        while !hit {
            let mut node_index = 0;
            let mut error = false;

            for i in 0..64 {
                if hit || error {
                    break;
                }
                let bit = self.bit_generator.generate();
                node_index <<= 1;

                if bit == 1 {
                    node_index += 1;
                }
                if self.first_non_zero <= i {
                    if i <= self.end_index {
                        ans = self.ddg_tree[node_index][(i - self.first_non_zero) as usize] as i64;
                    }
                    if ans >= 0 {
                        if ans != (self.matrix_size as i64 - 1) {
                            hit = true;
                        } else {
                            error = true;
                        }
                    } else if ans == -2 {
                        error = true;
                    }
                }
            }
        }
        ans - (self.fin as i64) + (self.mean as i64)
    }

    fn gen_i64_peikert(&mut self) -> i64 {
        let seed = StdRng::from_os_rng().sample(Open01);
        let ans = find_in_vector(&self.values, seed) as i64;

        ans - (self.fin as i64) + (self.mean as i64)
    }

    fn gen_ddg_tree(&mut self, prob_matrix: &[u64]) {
        self.first_non_zero = -1;
        for i in 0..64 {
            if self.first_non_zero != -1 {
                break;
            }

            if self.hamming_weights[i] != 0 {
                self.first_non_zero = i as isize;
            }
        }
        self.end_index = self.first_non_zero;
        let mut node_count = 1i32;
        for _ in 0..self.first_non_zero as usize {
            node_count <<= 1;
        }

        let mut end = false;
        let mut max_node_count = node_count;

        for i in self.first_non_zero as usize..64 {
            if end {
                break;
            }

            node_count <<= 1;
            self.end_index += 1;

            if node_count >= max_node_count {
                max_node_count = node_count;
            }

            node_count -= self.hamming_weights[i] as i32;

            if node_count <= 0 {
                end = true;
                if node_count < 0 {
                    self.end_index -= 1;
                }
            }
        }

        self.ddg_tree.resize(max_node_count as usize, vec![]);
        for i in 0..max_node_count as usize {
            self.ddg_tree[i].resize((self.end_index - self.first_non_zero) as usize, -2);
        }

        node_count = 1;

        for _ in 0..self.first_non_zero as usize {
            node_count <<= 1;
        }

        for i in self.first_non_zero as usize..self.end_index as usize {
            node_count <<= 1;
            node_count -= self.hamming_weights[i] as i32;

            for j in 0..node_count as usize {
                self.ddg_tree[j][i - self.first_non_zero as usize] = -1;
            }
            let mut e_node_count = 0;
            for j in 0..self.matrix_size {
                if e_node_count == self.hamming_weights[i] {
                    if (prob_matrix[j] >> (63 - i)) & 1 == 1 {
                        self.ddg_tree[(node_count as u32 + e_node_count) as usize]
                            [i - self.first_non_zero as usize] = j as i16;
                        e_node_count += 1;
                    }
                }
            }
        }
    }

    fn gen_prob_matrix(&mut self, mean: f64, std_dev: f64) {
        self.matrix_size = 2 * self.fin + 1;
        self.hamming_weights.resize(64, 0);
        self.std_dev = std_dev;
        let mut prob_matrix = Vec::<u64>::with_capacity(self.matrix_size);
        let mut probs = Vec::<f64>::with_capacity(self.matrix_size);
        let mut s = 0.0;
        let mut error = 1.0;

        for i in -1 * self.fin as isize..=self.fin as isize {
            let prob = E.powf(-(i as f64 - mean).powi(2) / (2.0 * std_dev * std_dev));
            s += prob;
            probs[i as usize + self.fin] = prob;
        }
        prob_matrix[self.matrix_size - 1] = (error * 2.0f64.powi(64)) as u64;
        for i in 0..self.matrix_size {
            let tmp = probs[i] * (1.0 / s);
            error -= tmp;
            prob_matrix[i] = (tmp * 2.0f64.powi(64)) as u64;
            for j in 0..64 {
                self.hamming_weights[j] += ((prob_matrix[i] >> (63 - j)) & 1) as u32;
            }
        }
        self.gen_ddg_tree(&prob_matrix);
    }

    fn initialize(&mut self, mean: f64) {
        self.values.clear();
        let variance = self.std_dev * self.std_dev;
        let mut cusum = 0.0;

        for x in -1 * self.fin as isize..=self.fin as isize {
            cusum += (-((x as f64 - mean).powi(2)) / (variance * 2.0)).exp();
        }

        self.b_a = 1.0 / cusum;

        self.values.reserve(2 * self.fin + 2);
        for i in -1 * self.fin as isize..=self.fin as isize {
            let temp = self.b_a * (-((i as f64 - mean).powi(2) / (2.0 * variance))).exp();
            self.values.push(temp);
        }

        let l = self.values.len();
        for i in 1..l {
            self.values[i] += self.values[i - 1];
        }
    }
}
