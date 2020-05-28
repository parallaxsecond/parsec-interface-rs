// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaGenerateKey operation
//!
//! Generate a key or a key pair.

use super::psa_key_attributes::Attributes;

/// Native object for creating a cryptographic key.
#[derive(Clone, Debug)]
pub struct Operation {
    /// `key_name` specifies a name by which the service will identify the key. Key
    /// name must be unique per application.
    pub key_name: String,
    /// `attributes` specifies the parameters to be associated with the key.
    pub attributes: Attributes,
}

/// Native object for the result of creating a cryptographic key.
///
/// The true result is returned in the `status` field of the response.
#[derive(Copy, Clone, Debug)]
pub struct Result;
