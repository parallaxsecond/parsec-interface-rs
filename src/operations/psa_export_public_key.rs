// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaExportPublicKey operation
//!
//! Export a key in binary format. See the book for the format description.

/// Native object for public key exporting operation.
#[derive(Debug)]
pub struct Operation {
    /// `key_name` identifies the key for which the public
    /// part will be exported. The specified key must be an asymmetric keypair.
    pub key_name: String,
}

/// Native object for result of public key export operation.
#[derive(Debug)]
pub struct Result {
    /// `data` holds the bytes defining the public key, formatted as specified
    /// by the provider for which the request was made.
    pub data: Vec<u8>,
}
