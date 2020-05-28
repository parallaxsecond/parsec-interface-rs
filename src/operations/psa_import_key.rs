// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaImportKey operation
//!
//! Import a key in binary format.

use super::psa_key_attributes::Attributes;

/// Native object for cryptographic key importing operation.
#[derive(Clone, Debug)]
pub struct Operation {
    /// `key_name` specifies a name by which the service will identify the key. Key
    /// name must be unique per application.
    pub key_name: String,
    /// `attributes` specifies the attributes for the new key.
    pub attributes: Attributes,
    /// `data` contains the bytes for the key,
    /// formatted in accordance with the requirements of the provider for the key type
    /// specified in `attributes`.
    pub data: Vec<u8>,
}

/// Native object for the result of a cryptographic key import operation.
///
/// The true result is sent in the `status` field of the response header.
#[derive(Copy, Clone, Debug)]
pub struct Result;
