// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaGenerateRandom operation
//!
//! Generate random bytes.

use derivative::Derivative;

/// Native object for creating a cryptographic key.
#[derive(Copy, Clone, Debug)]
pub struct Operation {
    /// `size` specifies how many random bytes to fetch.
    pub size: usize,
}

/// Native object for random bytes result.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// Random bytes.
    #[derivative(Debug = "ignore")]
    pub random_bytes: zeroize::Zeroizing<Vec<u8>>,
}
