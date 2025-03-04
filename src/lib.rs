/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: BSD-2
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
mod core;
pub mod error;
