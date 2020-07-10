// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaExportKey operation
//!
//! Export a key in binary format. See the book for the format description.

use derivative::Derivative;
/// Native object for key exporting operation.
#[derive(Debug)]
pub struct Operation {
    /// `key_name` identifies the key that will be exported.
    pub key_name: String,
}

/// Native object for result of key export operation.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// `data` holds the bytes defining the key, formatted as specified
    /// by the provider for which the request was made.
    #[derivative(Debug = "ignore")] // Don't output at debug - potentially contains private key
    pub data: secrecy::Secret<Vec<u8>>,
}
