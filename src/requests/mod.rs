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
//! # `Request`s and `Response`s
//!
//! A `Request` is what is sent to the service to execute one operation. A `Response` is what the
//! service returns.
use num_derive::FromPrimitive;

mod response_status;

pub mod utils;
pub mod request;
pub mod response;
pub use request::Request;
pub use response::Response;
pub use response_status::{ResponseStatus, Result};
use std::convert::TryFrom;

const MAGIC_NUMBER: u32 = 0x5EC0_A710;

/// Listing of provider types and their associated codes.
///
/// Passed in headers as `provider`.
#[derive(FromPrimitive, PartialEq, Eq, Hash, Copy, Clone, Debug)]
#[repr(u8)]
pub enum ProviderID {
    /// Provider to use for core PARSEC operations.
    CoreProvider = 0,
    /// Provider using Mbed Crypto software library.
    MbedProvider = 1,
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
#[derive(FromPrimitive, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum BodyType {
    /// Protobuf format for operations.
    Protobuf = 0,
}

/// Listing of available operations and their associated opcode.
///
/// Passed in headers as `opcode`. The values of the enumeration constants come from the operations
/// documentation available
/// [here](https://github.com/docker/parsec/blob/master/docs/operation_directory.proto).
#[derive(FromPrimitive, Copy, Clone, PartialEq, Debug, Hash, Eq)]
#[repr(u16)]
pub enum Opcode {
    Ping = 1,
    CreateKey = 2,
    DestroyKey = 3,
    AsymSign = 4,
    AsymVerify = 5,
    ImportKey = 6,
    ExportPublicKey = 7,
    ListProviders = 8,
    ListOpcodes = 9,
}

/// Listing of available authentication methods.
///
/// Passed in headers as `auth_type`.
#[derive(FromPrimitive, PartialEq, Eq, Hash, Copy, Clone, Debug)]
#[repr(u8)]
pub enum AuthType {
    /// Simple, dummy, authentication.
    Simple = 0,
}
