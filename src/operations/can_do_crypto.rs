// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # CanDoCrypto operation
//!
//! Checks if the provider supports the input attributes for the operations of a given type

use super::psa_key_attributes::Attributes;

/// Public enum which stores the options for the types of check
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum CheckType {
    /// Using a specific algorithm with an existing key.
    Use,
    /// Generating a key and optionally using it for a specific algorithm.
    Generate,
    /// Importing a key and optionally using it for a specific algorithm.
    Import,
    /// Deriving a key and optionally using it for a specific algorithm (to be checked)
    Derive,
}

/// Native object for client deleting operation.
#[derive(Clone, Debug, Copy)]
pub struct Operation {
    /// The type of check required
    pub check_type: CheckType,
    /// The attributes that are to be checked
    pub attributes: Attributes,
}

/// Native object for client deleting result.
#[derive(Copy, Clone, Debug)]
pub struct Result;
