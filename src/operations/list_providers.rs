// Copyright (c) 2019, Arm Limited, All Rights Reserved
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
use crate::requests::ProviderID;
use uuid::Uuid;

/// Structure holding the basic information that defines the providers in
/// the service for client discovery.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub uuid: Uuid,
    pub description: String,
    pub vendor: String,
    pub version_maj: u32,
    pub version_min: u32,
    pub version_rev: u32,
    pub id: ProviderID,
}

/// Native object for provider listing operation.
pub struct OpListProviders;

/// Native object for provider listing result.
///
/// A list of `ProviderInfo` structures, one for each provider available in
/// the service.
#[derive(Debug)]
pub struct ResultListProviders {
    pub providers: Vec<ProviderInfo>,
}
