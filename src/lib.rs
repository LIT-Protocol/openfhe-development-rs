/*
    Copyright LIT-Protocol. All Rights Reserved.
    SPDX-License-Identifier: BSD-2-Clause
*/
//! # Rust implementation of the OpenFHE library
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    clippy::mod_module_files
)]
#![deny(clippy::unwrap_used)]

#[macro_use]
mod macros;

pub mod constants;
pub mod context;
mod core;
pub mod encoding;
pub mod error;
pub mod pke;
mod serdes;

trait ActingPrimitive {
    type Primitive;
    fn to_primitive(&self) -> Self::Primitive;
}

impl ActingPrimitive for crypto_bigint::U64 {
    type Primitive = u64;

    fn to_primitive(&self) -> Self::Primitive {
        u64::from_be_bytes(self.to_be_bytes())
    }
}

impl ActingPrimitive for crypto_bigint::U128 {
    type Primitive = u128;

    fn to_primitive(&self) -> Self::Primitive {
        u128::from_be_bytes(self.to_be_bytes())
    }
}
