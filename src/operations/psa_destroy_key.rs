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
//! # PsaDestroyKey operation
//!
//! Destroy a key.

/// Native object for cryptographic key destruction.
#[derive(Debug, Clone)]
pub struct Operation {
    /// `key_name` identifies the key to be destroyed.
    pub key_name: String,
}

/// Native object for result of cryptographic key destruction.
///
/// True result of operation is returned in the response `status`.
#[derive(Copy, Clone, Debug)]
pub struct Result;
