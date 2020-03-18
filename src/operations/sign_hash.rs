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
//! # SignHash operation
//!
//! Sign an already-calculated hash with a private key.

use crate::operations::algorithm::AsymmetricSignature;

/// Native object for asymmetric sign operations.
#[derive(Debug)]
pub struct Operation {
    /// Defines which key should be used for the signing operation.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The input whose signature is to be verified. This is usually the hash of a message.
    pub hash: Vec<u8>,
}

/// Native object for asymmetric sign result.
#[derive(Debug)]
pub struct Result {
    /// The `signature` field contains the resulting bytes from the signing operation. The format of
    /// the signature is as specified by the provider doing the signing.
    pub signature: Vec<u8>,
}
