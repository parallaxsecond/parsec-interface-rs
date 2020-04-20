// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # ListProviders operation
//!
//! List the providers available in the service, with some information.
use crate::requests::ProviderID;
use uuid::Uuid;

/// Structure holding the basic information that defines the providers in
/// the service for client discovery.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Unique, permanent, identifier of the provider.
    pub uuid: Uuid,
    /// Short description of the provider.
    pub description: String,
    /// Provider vendor.
    pub vendor: String,
    /// Provider implementation version major.
    pub version_maj: u32,
    /// Provider implementation version minor.
    pub version_min: u32,
    /// Provider implementation version revision number.
    pub version_rev: u32,
    /// Provider ID to use on the wire protocol to communicate with this provider.
    pub id: ProviderID,
}

/// Native object for provider listing operation.
#[derive(Copy, Clone, Debug)]
pub struct Operation;

/// Native object for provider listing result.
#[derive(Debug)]
pub struct Result {
    /// A list of `ProviderInfo` structures, one for each provider available in
    /// the service.
    pub providers: Vec<ProviderInfo>,
}
