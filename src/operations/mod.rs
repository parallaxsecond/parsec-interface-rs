// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
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
pub mod psa_generate_key;
pub mod psa_import_key;
pub mod psa_export_public_key;
pub mod psa_export_key;
pub mod psa_destroy_key;
pub mod psa_sign_hash;
pub mod psa_verify_hash;
pub mod psa_hash_compute;
pub mod psa_hash_compare;
pub mod psa_asymmetric_encrypt;
pub mod psa_asymmetric_decrypt;
pub mod list_opcodes;
pub mod list_providers;
pub mod list_authenticators;
pub mod psa_generate_random;

pub use psa_crypto::types::algorithm as psa_algorithm;
pub use psa_crypto::types::key as psa_key_attributes;

use crate::requests::{request::RequestBody, response::ResponseBody, BodyType, Opcode, Result};

/// Container type for operation conversion values, holding a native operation object
/// to be passed in/out of a converter.
#[derive(Debug)]
pub enum NativeOperation {
    /// ListProviders operation
    ListProviders(list_providers::Operation),
    /// ListOpcodes operation
    ListOpcodes(list_opcodes::Operation),
    /// ListAuthenticators operation
    ListAuthenticators(list_authenticators::Operation),
    /// Ping operation
    Ping(ping::Operation),
    /// PsaGenerateKey operation
    PsaGenerateKey(psa_generate_key::Operation),
    /// PsaImportKey operation
    PsaImportKey(psa_import_key::Operation),
    /// PsaExportPublicKey operation
    PsaExportPublicKey(psa_export_public_key::Operation),
    /// PsaExportKey operation
    PsaExportKey(psa_export_key::Operation),
    /// PsaDestroyKey operation
    PsaDestroyKey(psa_destroy_key::Operation),
    /// PsaSignHash operation
    PsaSignHash(psa_sign_hash::Operation),
    /// PsaVerifyHash operation
    PsaVerifyHash(psa_verify_hash::Operation),
    /// PsaHashCompute operation
    PsaHashCompute(psa_hash_compute::Operation),
    /// PsaHashCompare operation
    PsaHashCompare(psa_hash_compare::Operation),
    /// PsaAsymmetricEncrypt operation
    PsaAsymmetricEncrypt(psa_asymmetric_encrypt::Operation),
    /// PsaAsymmetricDecrypt operation
    PsaAsymmetricDecrypt(psa_asymmetric_decrypt::Operation),
    /// PsaGenerateRandom operation
    PsaGenerateRandom(psa_generate_random::Operation),
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
            NativeOperation::PsaHashCompute(_) => Opcode::PsaHashCompute,
            NativeOperation::PsaHashCompare(_) => Opcode::PsaHashCompare,
            NativeOperation::PsaImportKey(_) => Opcode::PsaImportKey,
            NativeOperation::PsaExportPublicKey(_) => Opcode::PsaExportPublicKey,
            NativeOperation::PsaExportKey(_) => Opcode::PsaExportKey,
            NativeOperation::ListOpcodes(_) => Opcode::ListOpcodes,
            NativeOperation::ListProviders(_) => Opcode::ListProviders,
            NativeOperation::ListAuthenticators(_) => Opcode::ListAuthenticators,
            NativeOperation::PsaAsymmetricEncrypt(_) => Opcode::PsaAsymmetricEncrypt,
            NativeOperation::PsaAsymmetricDecrypt(_) => Opcode::PsaAsymmetricDecrypt,
            NativeOperation::PsaGenerateRandom(_) => Opcode::PsaGenerateRandom,
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
    /// ListAuthenticators result
    ListAuthenticators(list_authenticators::Result),
    /// Ping result
    Ping(ping::Result),
    /// PsaGenerateKey result
    PsaGenerateKey(psa_generate_key::Result),
    /// PsaImportKey result
    PsaImportKey(psa_import_key::Result),
    /// PsaExportPublicKey result
    PsaExportPublicKey(psa_export_public_key::Result),
    /// PsaExportKey result
    PsaExportKey(psa_export_key::Result),
    /// PsaDestroyKey result
    PsaDestroyKey(psa_destroy_key::Result),
    /// PsaSignHash result
    PsaSignHash(psa_sign_hash::Result),
    /// PsaHashCompute result
    PsaHashCompute(psa_hash_compute::Result),
    /// PsaHashCompare result
    PsaHashCompare(psa_hash_compare::Result),
    /// PsaVerifyHash result
    PsaVerifyHash(psa_verify_hash::Result),
    /// PsaAsymmetricEncrypt result
    PsaAsymmetricEncrypt(psa_asymmetric_encrypt::Result),
    /// PsaAsymmetricDecrypt result
    PsaAsymmetricDecrypt(psa_asymmetric_decrypt::Result),
    /// PsaGenerateRandom result
    PsaGenerateRandom(psa_generate_random::Result),
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
            NativeResult::PsaHashCompute(_) => Opcode::PsaHashCompute,
            NativeResult::PsaHashCompare(_) => Opcode::PsaHashCompare,
            NativeResult::PsaExportPublicKey(_) => Opcode::PsaExportPublicKey,
            NativeResult::PsaExportKey(_) => Opcode::PsaExportKey,
            NativeResult::ListOpcodes(_) => Opcode::ListOpcodes,
            NativeResult::ListProviders(_) => Opcode::ListProviders,
            NativeResult::ListAuthenticators(_) => Opcode::ListAuthenticators,
            NativeResult::PsaAsymmetricEncrypt(_) => Opcode::PsaAsymmetricEncrypt,
            NativeResult::PsaAsymmetricDecrypt(_) => Opcode::PsaAsymmetricDecrypt,
            NativeResult::PsaGenerateRandom(_) => Opcode::PsaGenerateRandom,
        }
    }
}

/// Definition of the operations converters must implement to allow usage of a specific
/// `BodyType`.
pub trait Convert {
    /// Get the `BodyType` associated with this converter.
    fn body_type(&self) -> BodyType;

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

impl From<list_providers::Operation> for NativeOperation {
    fn from(op: list_providers::Operation) -> Self {
        NativeOperation::ListProviders(op)
    }
}

impl From<list_opcodes::Operation> for NativeOperation {
    fn from(op: list_opcodes::Operation) -> Self {
        NativeOperation::ListOpcodes(op)
    }
}

impl From<list_authenticators::Operation> for NativeOperation {
    fn from(op: list_authenticators::Operation) -> Self {
        NativeOperation::ListAuthenticators(op)
    }
}

impl From<ping::Operation> for NativeOperation {
    fn from(op: ping::Operation) -> Self {
        NativeOperation::Ping(op)
    }
}

impl From<psa_generate_key::Operation> for NativeOperation {
    fn from(op: psa_generate_key::Operation) -> Self {
        NativeOperation::PsaGenerateKey(op)
    }
}

impl From<psa_import_key::Operation> for NativeOperation {
    fn from(op: psa_import_key::Operation) -> Self {
        NativeOperation::PsaImportKey(op)
    }
}

impl From<psa_export_public_key::Operation> for NativeOperation {
    fn from(op: psa_export_public_key::Operation) -> Self {
        NativeOperation::PsaExportPublicKey(op)
    }
}

impl From<psa_export_key::Operation> for NativeOperation {
    fn from(op: psa_export_key::Operation) -> Self {
        NativeOperation::PsaExportKey(op)
    }
}

impl From<psa_destroy_key::Operation> for NativeOperation {
    fn from(op: psa_destroy_key::Operation) -> Self {
        NativeOperation::PsaDestroyKey(op)
    }
}

impl From<psa_sign_hash::Operation> for NativeOperation {
    fn from(op: psa_sign_hash::Operation) -> Self {
        NativeOperation::PsaSignHash(op)
    }
}

impl From<psa_verify_hash::Operation> for NativeOperation {
    fn from(op: psa_verify_hash::Operation) -> Self {
        NativeOperation::PsaVerifyHash(op)
    }
}

impl From<psa_asymmetric_encrypt::Operation> for NativeOperation {
    fn from(op: psa_asymmetric_encrypt::Operation) -> Self {
        NativeOperation::PsaAsymmetricEncrypt(op)
    }
}

impl From<psa_asymmetric_decrypt::Operation> for NativeOperation {
    fn from(op: psa_asymmetric_decrypt::Operation) -> Self {
        NativeOperation::PsaAsymmetricDecrypt(op)
    }
}

impl From<psa_generate_random::Operation> for NativeOperation {
    fn from(op: psa_generate_random::Operation) -> Self {
        NativeOperation::PsaGenerateRandom(op)
    }
}

impl From<psa_hash_compute::Operation> for NativeOperation {
    fn from(op: psa_hash_compute::Operation) -> Self {
        NativeOperation::PsaHashCompute(op)
    }
}

impl From<psa_hash_compare::Operation> for NativeOperation {
    fn from(op: psa_hash_compare::Operation) -> Self {
        NativeOperation::PsaHashCompare(op)
    }
}

impl From<list_providers::Result> for NativeResult {
    fn from(op: list_providers::Result) -> Self {
        NativeResult::ListProviders(op)
    }
}

impl From<list_opcodes::Result> for NativeResult {
    fn from(op: list_opcodes::Result) -> Self {
        NativeResult::ListOpcodes(op)
    }
}

impl From<list_authenticators::Result> for NativeResult {
    fn from(op: list_authenticators::Result) -> Self {
        NativeResult::ListAuthenticators(op)
    }
}

impl From<ping::Result> for NativeResult {
    fn from(op: ping::Result) -> Self {
        NativeResult::Ping(op)
    }
}

impl From<psa_generate_key::Result> for NativeResult {
    fn from(op: psa_generate_key::Result) -> Self {
        NativeResult::PsaGenerateKey(op)
    }
}

impl From<psa_import_key::Result> for NativeResult {
    fn from(op: psa_import_key::Result) -> Self {
        NativeResult::PsaImportKey(op)
    }
}

impl From<psa_export_public_key::Result> for NativeResult {
    fn from(op: psa_export_public_key::Result) -> Self {
        NativeResult::PsaExportPublicKey(op)
    }
}

impl From<psa_export_key::Result> for NativeResult {
    fn from(op: psa_export_key::Result) -> Self {
        NativeResult::PsaExportKey(op)
    }
}

impl From<psa_destroy_key::Result> for NativeResult {
    fn from(op: psa_destroy_key::Result) -> Self {
        NativeResult::PsaDestroyKey(op)
    }
}

impl From<psa_sign_hash::Result> for NativeResult {
    fn from(op: psa_sign_hash::Result) -> Self {
        NativeResult::PsaSignHash(op)
    }
}

impl From<psa_verify_hash::Result> for NativeResult {
    fn from(op: psa_verify_hash::Result) -> Self {
        NativeResult::PsaVerifyHash(op)
    }
}

impl From<psa_hash_compute::Result> for NativeResult {
    fn from(op: psa_hash_compute::Result) -> Self {
        NativeResult::PsaHashCompute(op)
    }
}

impl From<psa_hash_compare::Result> for NativeResult {
    fn from(op: psa_hash_compare::Result) -> Self {
        NativeResult::PsaHashCompare(op)
    }
}

impl From<psa_asymmetric_encrypt::Result> for NativeResult {
    fn from(op: psa_asymmetric_encrypt::Result) -> Self {
        NativeResult::PsaAsymmetricEncrypt(op)
    }
}

impl From<psa_asymmetric_decrypt::Result> for NativeResult {
    fn from(op: psa_asymmetric_decrypt::Result) -> Self {
        NativeResult::PsaAsymmetricDecrypt(op)
    }
}

impl From<psa_generate_random::Result> for NativeResult {
    fn from(op: psa_generate_random::Result) -> Self {
        NativeResult::PsaGenerateRandom(op)
    }
}
