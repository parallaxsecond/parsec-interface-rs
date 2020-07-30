// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # Request and response definitions
//!
//! A `Request` is what is sent to the service to execute one operation. A `Response` is what the
//! service returns.
use num_derive::FromPrimitive;

pub mod response_status;

pub mod utils;
pub mod common;
pub mod request;
pub mod response;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
pub use request::Request;
pub use response::Response;
pub use response_status::{ResponseStatus, Result};
use std::convert::TryFrom;

/// Listing of provider types and their associated codes.
///
/// Passed in headers as `provider`.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(FromPrimitive, PartialEq, Eq, Hash, Copy, Clone, Debug)]
#[repr(u8)]
pub enum ProviderID {
    /// Provider to use for core Parsec operations.
    Core = 0,
    /// Provider using Mbed Crypto software library.
    MbedCrypto = 1,
    /// Provider using a PKCS 11 compatible library.
    Pkcs11 = 2,
    /// Provider using a TSS 2.0 Enhanced System API library.
    Tpm = 3,
}

impl std::fmt::Display for ProviderID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u8> for ProviderID {
    type Error = ResponseStatus;

    fn try_from(provider_id: u8) -> ::std::result::Result<Self, Self::Error> {
        match num::FromPrimitive::from_u8(provider_id) {
            Some(provider_id) => Ok(provider_id),
            None => Err(ResponseStatus::ProviderDoesNotExist),
        }
    }
}

/// Listing of body encoding types and their associated codes.
///
/// Passed in headers as `content_type` and `accept_type`.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(FromPrimitive, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum BodyType {
    /// Protobuf format for operations.
    Protobuf = 0,
}

/// Listing of available operations and their associated opcode.
///
/// Passed in headers as `opcode`. Check the
/// [Operations](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/index.html)
/// page of the book for more information.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(FromPrimitive, Copy, Clone, PartialEq, Debug, Hash, Eq)]
#[repr(u32)]
pub enum Opcode {
    /// Ping operation
    Ping = 1,
    /// PsaGenerateKey operation
    PsaGenerateKey = 2,
    /// PsaDestroyKey operation
    PsaDestroyKey = 3,
    /// PsaSignHash operation
    PsaSignHash = 4,
    /// PsaVerifyHash operation
    PsaVerifyHash = 5,
    /// PsaImportKey operation
    PsaImportKey = 6,
    /// PsaExportPublicKey operation
    PsaExportPublicKey = 7,
    /// ListProviders operation
    ListProviders = 8,
    /// ListOpcodes operation
    ListOpcodes = 9,
    /// PsaAsymmetricEncrypt operation
    PsaAsymmetricEncrypt = 10,
    /// PsaAsymmetricDecrypt operation
    PsaAsymmetricDecrypt = 11,
    /// PsaExportKey operation
    PsaExportKey = 12,
    /// PsaGenerateRandom operation
    PsaGenerateRandom = 13,
}

/// Listing of available authentication methods.
///
/// Passed in headers as `auth_type`.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(FromPrimitive, PartialEq, Eq, Hash, Copy, Clone, Debug)]
#[repr(u8)]
pub enum AuthType {
    /// No authentication
    NoAuth = 0,
    /// Direct authentication
    Direct = 1,
}
