// Copyright (c) 2019-2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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
