// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::requests::common::wire_header_1_0::WireHeader as Raw;
use crate::requests::{BodyType, Opcode, ProviderId, ResponseStatus, Result};
use num::FromPrimitive;
use std::convert::TryFrom;

/// A native representation of the response header.
///
/// Fields that are not relevant for application development (e.g. magic number) are
/// not copied across from the raw header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResponseHeader {
    /// Provider ID value
    pub provider: ProviderId,
    /// Session handle
    pub session: u64,
    /// Content type: defines how the request body should be processed.
    pub content_type: BodyType,
    /// Opcode of the operation to perform.
    pub opcode: Opcode,
    /// Response status of the request.
    pub status: ResponseStatus,
}

impl ResponseHeader {
    /// Create a new response header with default field values.
    pub(crate) fn new() -> ResponseHeader {
        ResponseHeader {
            provider: ProviderId::Core,
            session: 0,
            content_type: BodyType::Protobuf,
            opcode: Opcode::Ping,
            status: ResponseStatus::Success,
        }
    }
}

/// Conversion from the raw to native response header.
///
/// This conversion must be done before a `Response` value can be populated.
impl TryFrom<Raw> for ResponseHeader {
    type Error = ResponseStatus;

    fn try_from(header: Raw) -> Result<ResponseHeader> {
        let provider: ProviderId = match FromPrimitive::from_u8(header.provider) {
            Some(provider_id) => provider_id,
            None => return Err(ResponseStatus::ProviderDoesNotExist),
        };

        let content_type: BodyType = match FromPrimitive::from_u8(header.content_type) {
            Some(content_type) => content_type,
            None => return Err(ResponseStatus::ContentTypeNotSupported),
        };

        let opcode: Opcode = match FromPrimitive::from_u32(header.opcode) {
            Some(opcode) => opcode,
            None => return Err(ResponseStatus::OpcodeDoesNotExist),
        };

        let status: ResponseStatus = match FromPrimitive::from_u16(header.status) {
            Some(status) => status,
            None => return Err(ResponseStatus::InvalidEncoding),
        };

        Ok(ResponseHeader {
            provider,
            session: header.session,
            content_type,
            opcode,
            status,
        })
    }
}

/// Conversion from native to raw response header.
///
/// This is required in order to bring the contents of the header in a state
/// which can be serialized.
impl From<ResponseHeader> for Raw {
    fn from(header: ResponseHeader) -> Self {
        Raw {
            flags: 0,
            provider: header.provider as u8,
            session: header.session,
            content_type: header.content_type as u8,
            accept_type: 0,
            auth_type: 0,
            auth_len: 0,
            body_len: 0,
            opcode: header.opcode as u32,
            status: header.status as u16,
            reserved1: 0,
            reserved2: 0,
        }
    }
}
