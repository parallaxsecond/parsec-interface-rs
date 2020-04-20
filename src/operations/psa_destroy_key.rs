// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaDestroyKey operation
//!
//! Destroy a key.

/// Native object for cryptographic key destruction.
#[derive(Debug, Clone)]
pub struct Operation {
    /// `key_name` identifies the key to be destroyed.
    pub key_name: String,
}

/// Native object for result of cryptographic key destruction.
///
/// True result of operation is returned in the response `status`.
#[derive(Copy, Clone, Debug)]
pub struct Result;
