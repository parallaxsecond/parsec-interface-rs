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
//! # VerifyHash operation
//!
//! Verify the signature of a hash or short message using a public key.
use crate::operations::algorithm::AsymmetricSignature;

/// Native object for asymmetric verification of signatures.
#[derive(Debug)]
pub struct Operation {
    /// `key_name` specifies the key to be used for verification.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The `hash` contains a short message or hash value as described for the
    /// asymmetric signing operation.
    pub hash: Vec<u8>,
    /// Buffer containing the signature to verify.
    pub signature: Vec<u8>,
}

/// Native object for asymmetric verification of signatures.
///
/// The true result of the operation is sent as a `status` code in the response.
#[derive(Copy, Clone, Debug)]
pub struct Result;
