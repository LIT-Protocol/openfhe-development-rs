use subtle::{Choice, ConditionallySelectable};

/// Barrett reduction of 128-bit integer modulo 64-bit integer
///
/// a: operand (128-bit)
/// modulus: modulus (64-bit)
/// mu: 2^128/modulus (128-bit)
/// result: 64-bit integer a mod m
pub const fn barrett_reduction(a: u128, modulus: u64, mu: u128) -> u64 {
    let a_lo: u64 = a as u64;
    let a_hi: u64 = (a >> 64) as u64;
    let mu_lo: u64 = mu as u64;
    let mu_hi: u64 = (mu >> 64) as u64;

    let left_hi = mul_128_get_high(a_lo, mu_lo);

    let middle = mul_128(a_lo, mu_hi);
    let middle_lo = middle as u64;
    let middle_hi = (middle >> 64) as u64;

    let (tmp1, carry) = middle_lo.overflowing_add(left_hi);
    let tmp2 = middle_hi + (carry as u64);

    let middle = mul_128(a_hi, mu_lo);
    let middle_lo = middle as u64;
    let middle_hi = (middle >> 64) as u64;

    let carry = middle_lo.checked_add(tmp1).is_none();
    let left_hi = middle_hi + (carry as u64);

    let tmp1 = a_hi
        .wrapping_mul(mu_hi)
        .wrapping_add(tmp2)
        .wrapping_add(left_hi);

    let mut result = a_lo.wrapping_sub(tmp1.wrapping_mul(modulus));

    while result >= modulus {
        result = result.wrapping_sub(modulus);
    }

    result
}

// Helper function to compute the full 128-bit product of two 64-bit numbers
#[inline]
pub const fn mul_128(a: u64, b: u64) -> u128 {
    (a as u128) * (b as u128)
}

// Helper function to get only the high 64 bits of a 128-bit product
#[inline]
pub const fn mul_128_get_high(a: u64, b: u64) -> u64 {
    (((a as u128) * (b as u128)) >> 64) as u64
}

/// Compute phi of `n` which is the number of integers `m` coprime to `n` such that `1 <= m < n`
pub fn get_totient(n: usize) -> usize {
    let n = n as u64;
    let factors = prime_factorization::Factorization::run(n);
    let mut prime_prod = 1;
    let mut numerator = 1;
    for r in &factors.factors {
        numerator = numerator * *r - 1;
        prime_prod *= *r;
    }
    ((n / prime_prod) * numerator) as usize
}

/// `cyclotomic_order` must be a power of two
/// `modulus` must be a prime number
pub fn root_of_unity(cyclotomic_order: usize, modulus: usize) -> usize {
    if !cyclotomic_order.is_power_of_two() {
        panic!("`cyclotomic_order` must be a power of two");
    }
    let m = modulus as u64;
    let factors = prime_factorization::Factorization::run(m);
    if !factors.is_prime {
        panic!("`modulus` must be a prime number");
    }
    if (modulus - 1) % cyclotomic_order != 0 {
        panic!(
            "Please provide a prime modulus(q) and a cyclotomic number(m) satisfying the condition (q-1)/m is an integer. prime modulus({}) and modulus({}) do not satisfy this condition",
            modulus, cyclotomic_order
        );
    }

    let c = cyclotomic_order as u64;
    let generator = find_generator(m);
    let result = mod_pow(generator, (m - 1) / c, m);
    let mu = compute_mu(m);
    let mut x = mod_mul_eq(1, result, m, mu);
    let co_primes = get_coprimes(c);

    let mut min_ru = x;
    let mut cur_pow_idx = 1;

    for next_pow_idx in &co_primes {
        let diff_pow = next_pow_idx - cur_pow_idx;

        for _ in 0..diff_pow {
            x = mod_mul_eq(x, result, m, mu);
        }
        if x < min_ru && x != 1 {
            min_ru = x;
        }
        cur_pow_idx = *next_pow_idx;
    }

    min_ru as usize
}

pub fn get_coprimes(n: u64) -> Vec<u64> {
    let mut coprimes = Vec::new();
    for i in 1..n {
        if num::integer::gcd(i, n) == 1 {
            coprimes.push(i);
        }
    }
    coprimes
}

pub fn mod_mul_eq(a: u64, b: u64, modulus: u64, mu: u128) -> u64 {
    let result = mul_128(a, b);
    barrett_reduction(result, modulus, mu)
}

pub const fn compute_mu(modulus: u64) -> u128 {
    u128::MAX / modulus as u128 + 1
}

pub fn is_generator(generator: u64, modulus: u64) -> bool {
    let qm1 = modulus - 1;
    let prime_factors = prime_factorization::Factorization::run(qm1);
    let mut cnt = 0;
    for r in &prime_factors.factors {
        cnt += 1;
        if mod_pow(generator, qm1 / *r, modulus) == 1 {
            break;
        }
    }
    cnt == prime_factors.factors.len()
}

/// Find a generator for a given prime modulus
pub fn find_generator(modulus: u64) -> u64 {
    let qm2 = modulus - 2;
    loop {
        let g = rand::random::<u64>() % qm2 + 1;
        if is_generator(g, modulus) {
            return g;
        }
    }
}

pub fn mod_pow(base: u64, exponent: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }

    let mut result = 1;
    let mut base = base % modulus;
    let mut exponent = exponent;

    while exponent > 0 {
        let take = Choice::from((exponent & 1) as u8);
        let tmp = (result * base) % modulus;
        result.conditional_assign(&tmp, take);
        base = (base * base) % modulus;
        exponent >>= 1;
    }

    result
}

pub fn next_prime(candidate: u64) -> u64 {
    match candidate {
        0..=2 => 2,
        3 => 3,
        4 | 5 => 5,
        _ => {
            let k = candidate / 6;

            let o = if candidate % 6 < 2 { 1 } else { 5 };

            let mut x = 6 * k + o;
            let mut i = (3 + o) / 2;
            while !fermat(x) && !miller_rabin(x) {
                i ^= 6;
                x += i;
            }
            x
        }
    }
}

pub fn previous_prime(candidate: u64) -> u64 {
    match candidate {
        0 | 1 => 0,
        2 => 2,
        3 | 4 => 3,
        _ => {
            let mut x = if candidate & 1 == 0 {
                candidate - 1
            } else {
                candidate
            };

            let (o, mut i) = if x % 6 == 5 { (5, 4) } else { (1, 2) };

            x = (x / 6) * 6 + o;

            while !fermat(x) && !miller_rabin(x) {
                x -= i;
                i ^= 6;
            }
            x
        }
    }
}

pub fn fermat(candidate: u64) -> bool {
    let r = rand::random::<u64>() % candidate + 1;

    mod_pow(r, candidate - 1, candidate) == 1
}

pub fn miller_rabin(candidate: u64) -> bool {
    const LIMIT: usize = 12;
    if candidate < 3 {
        return false;
    }

    let cand_m1 = candidate - 1;
    let mut d = cand_m1;
    let mut trials = d.trailing_ones();

    if trials > 0 {
        d >>= trials;
    }
    if trials < 5 {
        trials = 5;
    }

    let bases = (0..LIMIT)
        .map(|_| rand::random::<u64>() % cand_m1 + 1)
        .collect::<Vec<u64>>();

    'next_base: for base in bases {
        let mut test = mod_pow(base, d, candidate);

        if test == 1 || test == cand_m1 {
            continue;
        }

        for _ in 1..trials - 1 {
            test = mod_pow(test, 2, candidate);

            if test == 1 {
                return false;
            } else if test == cand_m1 {
                break 'next_base;
            }
        }
        return false;
    }

    true
}
