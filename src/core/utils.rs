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
