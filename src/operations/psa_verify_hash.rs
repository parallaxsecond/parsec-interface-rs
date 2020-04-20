// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaVerifyHash operation
//!
//! Verify the signature of a hash or short message using a public key.
use crate::operations::psa_algorithm::AsymmetricSignature;

/// Native object for asymmetric verification of signatures.
#[derive(Debug)]
pub struct Operation {
    /// `key_name` specifies the key to be used for verification.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The `hash` contains a short message or hash value as described for the
    /// asymmetric signing operation.
    pub hash: Vec<u8>,
    /// Buffer containing the signature to verify.
    pub signature: Vec<u8>,
}

/// Native object for asymmetric verification of signatures.
///
/// The true result of the operation is sent as a `status` code in the response.
#[derive(Copy, Clone, Debug)]
pub struct Result;
