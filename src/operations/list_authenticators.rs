// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # ListAuthenticators operation
//!
//! List the authenticators available in the service.
use crate::requests::AuthType;
use std::cmp::Eq;

/// Structure holding the basic information that defines the authenticators in the service for
/// client discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatorInfo {
    /// Short description of the authenticator.
    pub description: String,
    /// Authenticator implementation version major.
    pub version_maj: u32,
    /// Authenticator implementation version minor.
    pub version_min: u32,
    /// Authenticator implementation version revision number.
    pub version_rev: u32,
    /// Authenticator ID to use on the wire protocol to communicate with this authenticator.
    pub id: AuthType,
}

/// Native object for authenticator listing operation.
#[derive(Copy, Clone, Debug)]
pub struct Operation;

/// Native object for authenticator listing result.
#[derive(Debug)]
pub struct Result {
    /// A list of `AuthenticatorInfo` structures, one for each authenticator available in
    /// the service.
    pub authenticators: Vec<AuthenticatorInfo>,
}
