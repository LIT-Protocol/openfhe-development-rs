pub fn eval_chebyshev_coefficients<F>(f: F, a: f64, b: f64, degree: usize) -> Vec<f64>
where
    F: Fn(f64) -> f64,
{
    let coeff_total = degree + 1;
    let minus_a = 0.5 * (b - a);
    let plus_a = 0.5 * (b + a);
    let pi_by_degree = std::f64::consts::PI / coeff_total as f64;

    let function_points = (0..coeff_total)
        .map(|i| {
            let ii = i as f64;
            let input = f64::cos(pi_by_degree * (ii + 0.5));
            let x = minus_a * input + plus_a;
            f(x)
        })
        .collect::<Vec<_>>();

    let mul_factor = 2.0 / coeff_total as f64;

    (0..coeff_total)
        .map(|i| {
            let ii = i as f64;
            let mut sum = 0.0;
            for (j, &y) in function_points.iter().enumerate() {
                let jj = j as f64;
                sum += y * f64::cos(pi_by_degree * ii * (jj + 0.5));
            }
            sum * mul_factor
        })
        .collect()
}
