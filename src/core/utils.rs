use crate::ActingPrimitive;
use crypto_bigint::{
    Monty, NonZero, Odd, RandomMod, U64, modular::MontyForm, rand_core::SeedableRng,
};

/// Compute phi of `n` which is the number of integers `m` coprime to `n` such that `1 <= m < n`
pub fn get_totient(n: U64) -> U64 {
    let n = n.to_primitive();
    let factors = prime_factorization::Factorization::<u64>::run(n);
    let mut prime_prod = 1;
    let mut numerator = 1;
    for r in &factors.factors {
        numerator *= *r - 1;
        prime_prod *= *r;
    }
    U64::from_u64((n / prime_prod) * numerator)
}

/// `cyclotomic_order` must be a power of two
/// `modulus` must be a prime number
pub fn root_of_unity(cyclotomic_order: U64, modulus: Odd<U64>) -> U64 {
    let order: u64 = cyclotomic_order.to_primitive();
    let modu: u64 = modulus.get().to_primitive();
    if !order.is_power_of_two() {
        panic!("`cyclotomic_order` must be a power of two");
    }
    let factors = prime_factorization::Factorization::run(modu);
    if !factors.is_prime {
        panic!("`modulus` must be a prime number");
    }
    if (modu - 1) % order == 0 {
        panic!(
            "Please provide a prime modulus(q) and a cyclotomic number(m) satisfying the condition (q-1)/m is an integer. prime modulus({}) and modulus({}) do not satisfy this condition",
            modu, order
        );
    }

    let co_primes = get_coprimes(cyclotomic_order);
    let params = MontyForm::new_params_vartime(modulus);

    let generator = find_generator(modulus);
    let generator = MontyForm::new(&generator, params);
    let one = MontyForm::one(params);
    let exponent: U64 = (modulus.get() - U64::ONE) / NonZero::<U64>::new_unwrap(cyclotomic_order);

    let result = generator.pow(&exponent);
    let mut x = result;

    let mut min_ru = x;
    let mut cur_pow_idx = 1u64;

    for next_pow_idx in &co_primes {
        let next_pow_idx: u64 = next_pow_idx.to_primitive();
        let diff_pow = next_pow_idx - cur_pow_idx;

        for _ in 0..diff_pow {
            x = x.mul(&result);
        }
        let lhs = x.retrieve();
        let rhs = min_ru.retrieve();
        if lhs < rhs && x != one {
            min_ru = x;
        }
        cur_pow_idx = next_pow_idx;
    }

    min_ru.retrieve()
}

pub fn get_coprimes(n: U64) -> Vec<U64> {
    let mut coprimes = Vec::new();
    let mut i = U64::ONE;
    while i < n {
        if i.gcd(&n) == U64::ONE {
            coprimes.push(i);
        }

        i += U64::ONE;
    }
    coprimes
}

pub fn is_generator(generator: U64, modulus: Odd<U64>) -> bool {
    let qm1: U64 = modulus.get() - U64::ONE;
    let qm1_u64: u64 = qm1.to_primitive();

    let params = MontyForm::<{ U64::LIMBS }>::new_params_vartime(modulus);
    let one = MontyForm::<{ U64::LIMBS }>::one(params);
    let generator = MontyForm::<{ U64::LIMBS }>::new(&generator, params);

    let prime_factors = prime_factorization::Factorization::run(qm1_u64);
    let mut cnt = 0;
    for r in &prime_factors.factors {
        let r = NonZero::<U64>::new_unwrap(U64::from_u64(*r));
        let exponent = qm1 / r;
        cnt += 1;
        if generator.pow(&exponent) == one {
            break;
        }
    }
    cnt == prime_factors.factors.len()
}

/// Find a generator for a given prime modulus
pub fn find_generator(modulus: Odd<U64>) -> U64 {
    // This function isn't cryptographically required to be secure since its just testing
    // the generator property of the given modulus so ChaCha8Rng is ok
    let mut rng = rand_chacha::ChaCha8Rng::from_os_rng();
    let qm2: NonZero<U64> = NonZero::<U64>::new_unwrap(modulus.get() - U64::from_u64(2));
    loop {
        let g = U64::random_mod(&mut rng, &qm2) + U64::ONE;
        if is_generator(g, modulus) {
            return g;
        }
    }
}

pub fn next_prime(starting_number: U64, cyclotomic_order: U64) -> U64 {
    let mut rng = rand_chacha::ChaCha8Rng::from_os_rng();
    let mut n = starting_number + cyclotomic_order;
    while !crypto_primes::is_prime_with_rng(&mut rng, &n) {
        n += cyclotomic_order;
    }
    n
}

pub fn previous_prime(starting_number: U64, cyclotomic_order: U64) -> U64 {
    let mut rng = rand_chacha::ChaCha8Rng::from_os_rng();
    let mut n = starting_number - cyclotomic_order;
    while !crypto_primes::is_prime_with_rng(&mut rng, &n) {
        n -= cyclotomic_order;
    }
    n
}

pub fn reverse_bits(n: usize, bits: usize) -> usize {
    let mut result = 0;
    for i in 0..bits {
        if n & (1 << i) != 0 {
            result |= 1 << (bits - 1 - i);
        }
    }
    result
}
