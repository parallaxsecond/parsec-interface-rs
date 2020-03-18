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
//! # Rust representation of operations
//!
//! Rust native representation of the language neutral operations described in the
//! [Operations](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/index.html)
//! page in the book.
//! Some of the doc comments have directly been taken from the PSA Crypto API document version
//! 1.0.0. Please check that
//! [document](https://developer.arm.com/architectures/security-architectures/platform-security-architecture/documentation)
//! and the book for more details.
pub mod ping;
pub mod key_attributes;
pub mod algorithm;
pub mod generate_key;
pub mod import_key;
pub mod export_public_key;
pub mod destroy_key;
pub mod sign_hash;
pub mod verify_hash;
pub mod list_opcodes;
pub mod list_providers;

use crate::requests::{request::RequestBody, response::ResponseBody, Opcode, Result};

/// Container type for operation conversion values, holding a native operation object
/// to be passed in/out of a converter.
#[derive(Debug)]
pub enum NativeOperation {
    /// ListProviders operation
    ListProviders(list_providers::Operation),
    /// ListOpcodes operation
    ListOpcodes(list_opcodes::Operation),
    /// Ping operation
    Ping(ping::Operation),
    /// GenerateKey operation
    GenerateKey(generate_key::Operation),
    /// ImportKey operation
    ImportKey(import_key::Operation),
    /// ExportPublicKey operation
    ExportPublicKey(export_public_key::Operation),
    /// DestroyKey operation
    DestroyKey(destroy_key::Operation),
    /// SignHash operation
    SignHash(sign_hash::Operation),
    /// VerifyHash operation
    VerifyHash(verify_hash::Operation),
}

impl NativeOperation {
    /// Return the opcode of the operation associated.
    pub fn opcode(&self) -> Opcode {
        match self {
            NativeOperation::Ping(_) => Opcode::Ping,
            NativeOperation::GenerateKey(_) => Opcode::GenerateKey,
            NativeOperation::DestroyKey(_) => Opcode::DestroyKey,
            NativeOperation::SignHash(_) => Opcode::SignHash,
            NativeOperation::VerifyHash(_) => Opcode::VerifyHash,
            NativeOperation::ImportKey(_) => Opcode::ImportKey,
            NativeOperation::ExportPublicKey(_) => Opcode::ExportPublicKey,
            NativeOperation::ListOpcodes(_) => Opcode::ListOpcodes,
            NativeOperation::ListProviders(_) => Opcode::ListProviders,
        }
    }
}

/// Container type for result conversion values, holding a native result object to be
/// passed in/out of the converter.
#[derive(Debug)]
pub enum NativeResult {
    /// ListProviders result
    ListProviders(list_providers::Result),
    /// ListOpcodes result
    ListOpcodes(list_opcodes::Result),
    /// Ping result
    Ping(ping::Result),
    /// GenerateKey result
    GenerateKey(generate_key::Result),
    /// ImportKey result
    ImportKey(import_key::Result),
    /// ExportPublicKey result
    ExportPublicKey(export_public_key::Result),
    /// DestroyKey result
    DestroyKey(destroy_key::Result),
    /// SignHash result
    SignHash(sign_hash::Result),
    /// VerifyHash result
    VerifyHash(verify_hash::Result),
}

impl NativeResult {
    /// Return the opcode of the operation associated.
    pub fn opcode(&self) -> Opcode {
        match self {
            NativeResult::Ping(_) => Opcode::Ping,
            NativeResult::GenerateKey(_) => Opcode::GenerateKey,
            NativeResult::DestroyKey(_) => Opcode::DestroyKey,
            NativeResult::SignHash(_) => Opcode::SignHash,
            NativeResult::VerifyHash(_) => Opcode::VerifyHash,
            NativeResult::ImportKey(_) => Opcode::ImportKey,
            NativeResult::ExportPublicKey(_) => Opcode::ExportPublicKey,
            NativeResult::ListOpcodes(_) => Opcode::ListOpcodes,
            NativeResult::ListProviders(_) => Opcode::ListProviders,
        }
    }
}

/// Definition of the operations converters must implement to allow usage of a specific
/// `BodyType`.
pub trait Convert {
    /// Create a native operation object from a request body.
    ///
    /// # Errors
    /// - if deserialization fails, `ResponseStatus::DeserializingBodyFailed` is returned
    fn body_to_operation(&self, body: RequestBody, opcode: Opcode) -> Result<NativeOperation>;

    /// Create a request body from a native operation object.
    ///
    /// # Errors
    /// - if serialization fails, `ResponseStatus::SerializingBodyFailed` is returned
    fn operation_to_body(&self, operation: NativeOperation) -> Result<RequestBody>;

    /// Create a native result object from a response body.
    ///
    /// # Errors
    /// - if deserialization fails, `ResponseStatus::DeserializingBodyFailed` is returned
    fn body_to_result(&self, body: ResponseBody, opcode: Opcode) -> Result<NativeResult>;

    /// Create a response body from a native result object.
    ///
    /// # Errors
    /// - if serialization fails, `ResponseStatus::SerializingBodyFailed` is returned
    fn result_to_body(&self, result: NativeResult) -> Result<ResponseBody>;
}
