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
//! # Ping operation
//!
//! The Ping operation is used to check if the service is alive and determine the highest wire
//! protocol version a client can use.

/// Native object for Ping operation.
#[derive(Copy, Clone, Debug)]
pub struct Operation;

/// Native object for Ping result.
///
/// The latest wire protocol version supported by the service. The version is represented as `x.y`
/// where `x` is the version major and `y` the version minor.
#[derive(Copy, Clone, Debug)]
pub struct Result {
    /// Supported latest wire protocol version major
    pub wire_protocol_version_maj: u8,
    /// Supported latest wire protocol version minor
    pub wire_protocol_version_min: u8,
}
