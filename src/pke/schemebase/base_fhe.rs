use crate::pke::crypto_context::CryptoContext;
use std::collections::HashMap;

pub trait FheBase {
    /// `level_budget` budgets for the amount of levels in encoding and decoding
    /// `dimension1` inner dimension in the base-step giant-step routing
    /// for encoding and decoding
    /// `slots` numer of slots to be bootstrapped
    /// `correction_factor` value to rescale message by to improve precision.
    /// If set to 0, use default logic.
    /// `precompute` whether to precompute the plaintexts for encoding and decoding
    fn eval_bootstrap_setup(
        cc: &CryptoContext,
        level_budget: &[usize],
        dimension1: &[usize],
        slots: usize,
        correction_factor: usize,
        precompute: bool,
    );

    fn eval_bootstrap_key_gen() -> HashMap<usize, EvalKey<Element>>;
}
