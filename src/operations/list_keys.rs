// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # ListKeys operation
//!
//! Lists all keys belonging to the application.
use super::psa_key_attributes::Attributes;
use crate::requests::ProviderID;

/// Structure holding the basic information for a key in the application for client discovery.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyInfo {
    /// The ID of the associated provider.
    pub provider_id: ProviderID,
    /// The name of the key.
    pub name: String,
    /// The key attributes.
    pub attributes: Attributes,
}

/// Native object for key listing operation.
#[derive(Copy, Clone, Debug)]
pub struct Operation;

/// Native object for key listing result.
#[derive(Debug)]
pub struct Result {
    /// A list of `KeyInfo` structures.
    pub keys: Vec<KeyInfo>,
}
