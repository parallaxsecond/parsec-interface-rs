// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaHashCompare operation
//!
//! Compute the hash value of a message and compare it with a reference value.

use crate::operations::psa_algorithm::Hash;
use derivative::Derivative;

/// Native object for hash compare operations.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// The hash algorithm to compute.
    pub alg: Hash,
    /// The input to hash.
    #[derivative(Debug = "ignore")]
    pub input: zeroize::Zeroizing<Vec<u8>>,
    /// The reference hash value.
    #[derivative(Debug = "ignore")]
    pub hash: zeroize::Zeroizing<Vec<u8>>,
}

/// Native object for hash compare result.
#[derive(Debug, Default, Copy, Clone)]
pub struct Result;
