// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaImportKey operation
//!
//! Import a key in binary format.

use super::psa_key_attributes::Attributes;
use derivative::Derivative;

/// Native object for cryptographic key importing operation.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// `key_name` specifies a name by which the service will identify the key. Key
    /// name must be unique per application.
    pub key_name: String,
    /// `attributes` specifies the attributes for the new key.
    pub attributes: Attributes,
    /// `data` contains the bytes for the key,
    /// formatted in accordance with the requirements of the provider for the key type
    /// specified in `attributes`.
    // Debug is not derived for this because it could expose secrets if printed or logged
    // somewhere
    #[derivative(Debug = "ignore")]
    pub data: crate::secrecy::Secret<Vec<u8>>,
}

/// Native object for the result of a cryptographic key import operation.
///
/// The true result is sent in the `status` field of the response header.
#[derive(Copy, Clone, Debug)]
pub struct Result;
