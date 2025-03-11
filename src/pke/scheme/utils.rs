pub fn compute_num_large_digits(num_large_digits: usize, mult_depth: usize) -> usize {
    if num_large_digits > 0 {
        return num_large_digits;
    }
    if mult_depth > 3 {
        return 3;
    }
    if mult_depth > 0 {
        return 2;
    }
    1
}

pub fn compute_num_large_digits_pre(num_large_digits: usize, num_hops: usize) -> usize {
    if num_large_digits > 0 {
        return num_large_digits;
    }
    if num_hops > 4 {
        return 3;
    }
    if num_hops > 1 {
        return 2;
    }
    1
}
