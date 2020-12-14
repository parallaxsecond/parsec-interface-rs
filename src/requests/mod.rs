// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # Request and response definitions
//!
//! A `Request` is what is sent to the service to execute one operation. A `Response` is what the
//! service returns.
use num_derive::FromPrimitive;

mod response_status;

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
    /// Provider using the crypto Trusted Service running in TrustZone
    TrustedService = 4,
    /// Provider using the MicrochipTech cryptodevice ATECCx08 via CryptoAuthentication Library
    CryptoAuthLib = 5,
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
    Ping = 0x0001,
    /// PsaGenerateKey operation
    PsaGenerateKey = 0x0002,
    /// PsaDestroyKey operation
    PsaDestroyKey = 0x0003,
    /// PsaSignHash operation
    PsaSignHash = 0x0004,
    /// PsaVerifyHash operation
    PsaVerifyHash = 0x0005,
    /// PsaImportKey operation
    PsaImportKey = 0x0006,
    /// PsaExportPublicKey operation
    PsaExportPublicKey = 0x0007,
    /// ListProviders operation
    ListProviders = 0x0008,
    /// ListOpcodes operation
    ListOpcodes = 0x0009,
    /// PsaAsymmetricEncrypt operation
    PsaAsymmetricEncrypt = 0x000A,
    /// PsaAsymmetricDecrypt operation
    PsaAsymmetricDecrypt = 0x000B,
    /// PsaExportKey operation
    PsaExportKey = 0x000C,
    /// PsaGenerateRandom operation
    PsaGenerateRandom = 0x000D,
    /// ListAuthenticators operation
    ListAuthenticators = 0x000E,
    /// PsaHashCompute operation
    PsaHashCompute = 0x000F,
    /// PsaHashCompare operation
    PsaHashCompare = 0x0010,
    /// PsaAeadEncrypt
    PsaAeadEncrypt = 0x0011,
    /// PsaAeadDecrypt
    PsaAeadDecrypt = 0x0012,
    /// PsaRawKeyAgreement operation
    PsaRawKeyAgreement = 0x0013,
    /// ListKeys operations
    ListKeys = 0x001A,
}

impl Opcode {
    /// Check if an opcode is one of a Core operation
    pub fn is_core(&self) -> bool {
        // match to ensure exhaustivity when a new opcode is added
        match self {
            Opcode::Ping => true,
            Opcode::ListProviders => true,
            Opcode::ListOpcodes => true,
            Opcode::ListAuthenticators => true,
            Opcode::ListKeys => true,
            Opcode::PsaGenerateKey => false,
            Opcode::PsaDestroyKey => false,
            Opcode::PsaSignHash => false,
            Opcode::PsaVerifyHash => false,
            Opcode::PsaImportKey => false,
            Opcode::PsaExportPublicKey => false,
            Opcode::PsaAsymmetricEncrypt => false,
            Opcode::PsaAsymmetricDecrypt => false,
            Opcode::PsaExportKey => false,
            Opcode::PsaGenerateRandom => false,
            Opcode::PsaHashCompute => false,
            Opcode::PsaHashCompare => false,
            Opcode::PsaAeadEncrypt => false,
            Opcode::PsaAeadDecrypt => false,
            Opcode::PsaRawKeyAgreement => false,
        }
    }

    /// Check if an opcode is one of a PSA Crypto operation
    pub fn is_crypto(&self) -> bool {
        !self.is_core()
    }
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
    /// JSON Web Tokens (JWT) authentication (not currently supported)
    Jwt = 2,
    /// Unix peer credentials authentication
    UnixPeerCredentials = 3,
    /// Authentication verifying a JWT SPIFFE Verifiable Identity Document
    JwtSvid = 4,
}

#[test]
fn check_opcode_nature() {
    assert!(Opcode::ListKeys.is_core());
    assert!(!Opcode::ListKeys.is_crypto());
    assert!(Opcode::PsaGenerateKey.is_crypto());
}
