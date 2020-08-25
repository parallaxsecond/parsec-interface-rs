// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::requests::common::wire_header_1_0::WireHeader as Raw;
use crate::requests::ResponseStatus;
use crate::requests::{AuthType, BodyType, Opcode, ProviderID};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use num::FromPrimitive;
use std::convert::TryFrom;

/// A native representation of the request header.
///
/// Fields that are not relevant for application development (e.g. magic number) are
/// not copied across from the raw header.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RequestHeader {
    /// Provider ID value
    pub provider: ProviderID,
    /// Session handle
    pub session: u64,
    /// Content type: defines how the request body should be processed.
    pub content_type: BodyType,
    /// Accept type: defines how the service should provide its response.
    pub accept_type: BodyType,
    /// Authentication type.
    pub auth_type: AuthType,
    /// Opcode of the operation to perform.
    pub opcode: Opcode,
}

impl RequestHeader {
    /// Create a new request header with default field values.
    /// Available for testing only.
    #[cfg(feature = "testing")]
    pub(crate) fn new() -> RequestHeader {
        RequestHeader {
            provider: ProviderID::core(),
            session: 0,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            auth_type: AuthType::Direct,
            opcode: Opcode::Ping,
        }
    }
}

/// Conversion from the raw to native request header.
///
/// This conversion must be done before a `Request` value can be populated.
impl TryFrom<Raw> for RequestHeader {
    type Error = ResponseStatus;

    fn try_from(header: Raw) -> ::std::result::Result<Self, Self::Error> {
        let content_type: BodyType = match FromPrimitive::from_u8(header.content_type) {
            Some(content_type) => content_type,
            None => return Err(ResponseStatus::ContentTypeNotSupported),
        };

        let accept_type: BodyType = match FromPrimitive::from_u8(header.accept_type) {
            Some(accept_type) => accept_type,
            None => return Err(ResponseStatus::AcceptTypeNotSupported),
        };

        let auth_type: AuthType = match FromPrimitive::from_u8(header.auth_type) {
            Some(auth_type) => auth_type,
            None => return Err(ResponseStatus::AuthenticatorDoesNotExist),
        };

        let opcode: Opcode = match FromPrimitive::from_u32(header.opcode) {
            Some(opcode) => opcode,
            None => return Err(ResponseStatus::OpcodeDoesNotExist),
        };

        Ok(RequestHeader {
            provider: ProviderID::try_from(header.provider)?,
            session: header.session,
            content_type,
            accept_type,
            auth_type,
            opcode,
        })
    }
}

/// Conversion from native to raw request header.
///
/// This is required in order to bring the contents of the header in a state
/// which can be serialized.
impl From<RequestHeader> for Raw {
    fn from(header: RequestHeader) -> Self {
        Raw {
            flags: 0,
            provider: header.provider.id(),
            session: header.session,
            content_type: header.content_type as u8,
            accept_type: header.accept_type as u8,
            auth_type: header.auth_type as u8,
            body_len: 0,
            auth_len: 0,
            opcode: header.opcode as u32,
            status: 0, // status field unused
            reserved1: 0,
            reserved2: 0,
        }
    }
}
