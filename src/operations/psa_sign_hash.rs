// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaSignHash operation
//!
//! Sign an already-calculated hash with a private key.

use crate::operations::psa_algorithm::AsymmetricSignature;

/// Native object for asymmetric sign operations.
#[derive(Debug)]
pub struct Operation {
    /// Defines which key should be used for the signing operation.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The input whose signature is to be verified. This is usually the hash of a message.
    pub hash: Vec<u8>,
}

/// Native object for asymmetric sign result.
#[derive(Debug)]
pub struct Result {
    /// The `signature` field contains the resulting bytes from the signing operation. The format of
    /// the signature is as specified by the provider doing the signing.
    pub signature: Vec<u8>,
}
