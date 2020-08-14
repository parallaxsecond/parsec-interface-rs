// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaHashCompute operation
//!
//! Compute the hash value of a message.

use crate::operations::psa_algorithm::Hash;
use derivative::Derivative;

/// Native object for hash compute operations.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// The hash algorithm to compute.
    pub alg: Hash,
    /// The input to hash.
    #[derivative(Debug = "ignore")]
    pub input: zeroize::Zeroizing<Vec<u8>>,
}

/// Native object for hash compute result.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// The `hash` field contains the hash of the message.
    #[derivative(Debug = "ignore")]
    pub hash: zeroize::Zeroizing<Vec<u8>>,
}
