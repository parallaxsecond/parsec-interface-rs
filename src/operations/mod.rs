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
pub mod psa_key_attributes;
pub mod psa_algorithm;
pub mod psa_generate_key;
pub mod psa_import_key;
pub mod psa_export_public_key;
pub mod psa_destroy_key;
pub mod psa_sign_hash;
pub mod psa_verify_hash;
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
    /// PsaGenerateKey operation
    PsaGenerateKey(psa_generate_key::Operation),
    /// PsaImportKey operation
    PsaImportKey(psa_import_key::Operation),
    /// PsaExportPublicKey operation
    PsaExportPublicKey(psa_export_public_key::Operation),
    /// PsaDestroyKey operation
    PsaDestroyKey(psa_destroy_key::Operation),
    /// PsaSignHash operation
    PsaSignHash(psa_sign_hash::Operation),
    /// PsaVerifyHash operation
    PsaVerifyHash(psa_verify_hash::Operation),
}

impl NativeOperation {
    /// Return the opcode of the operation associated.
    pub fn opcode(&self) -> Opcode {
        match self {
            NativeOperation::Ping(_) => Opcode::Ping,
            NativeOperation::PsaGenerateKey(_) => Opcode::PsaGenerateKey,
            NativeOperation::PsaDestroyKey(_) => Opcode::PsaDestroyKey,
            NativeOperation::PsaSignHash(_) => Opcode::PsaSignHash,
            NativeOperation::PsaVerifyHash(_) => Opcode::PsaVerifyHash,
            NativeOperation::PsaImportKey(_) => Opcode::PsaImportKey,
            NativeOperation::PsaExportPublicKey(_) => Opcode::PsaExportPublicKey,
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
    /// PsaGenerateKey result
    PsaGenerateKey(psa_generate_key::Result),
    /// PsaImportKey result
    PsaImportKey(psa_import_key::Result),
    /// PsaExportPublicKey result
    PsaExportPublicKey(psa_export_public_key::Result),
    /// PsaDestroyKey result
    PsaDestroyKey(psa_destroy_key::Result),
    /// PsaSignHash result
    PsaSignHash(psa_sign_hash::Result),
    /// PsaVerifyHash result
    PsaVerifyHash(psa_verify_hash::Result),
}

impl NativeResult {
    /// Return the opcode of the operation associated.
    pub fn opcode(&self) -> Opcode {
        match self {
            NativeResult::Ping(_) => Opcode::Ping,
            NativeResult::PsaGenerateKey(_) => Opcode::PsaGenerateKey,
            NativeResult::PsaDestroyKey(_) => Opcode::PsaDestroyKey,
            NativeResult::PsaSignHash(_) => Opcode::PsaSignHash,
            NativeResult::PsaVerifyHash(_) => Opcode::PsaVerifyHash,
            NativeResult::PsaImportKey(_) => Opcode::PsaImportKey,
            NativeResult::PsaExportPublicKey(_) => Opcode::PsaExportPublicKey,
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
