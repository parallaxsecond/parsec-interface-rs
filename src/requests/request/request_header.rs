// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::requests::MAGIC_NUMBER;
use crate::requests::{AuthType, BodyType, Opcode, ProviderID};
use crate::requests::{ResponseStatus, Result};
use crate::requests::{WIRE_PROTOCOL_VERSION_MAJ, WIRE_PROTOCOL_VERSION_MIN};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use log::error;
use num::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{Read, Write};

const REQUEST_HDR_SIZE: u16 = 22;

/// Raw representation of a request header, as defined for the wire format.
///
/// Serialisation and deserialisation are handled by `serde`, also in tune with the
/// wire format (i.e. little-endian, native encoding).
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Raw {
    /// Provider ID value
    pub provider: u8,
    /// Session handle
    pub session: u64,
    /// Content type: defines how the request body should be processed.
    pub content_type: u8,
    /// Accept type: defines how the service should provide its response.
    pub accept_type: u8,
    /// Authentication type.
    pub auth_type: u8,
    /// Number of bytes of content.
    pub body_len: u32,
    /// Number of bytes of authentication.
    pub auth_len: u16,
    /// Opcode of the operation to perform.
    pub opcode: u16,
}

impl Raw {
    /// Create a new raw request header.
    ///
    /// For use in testing only.
    #[cfg(feature = "testing")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Raw {
        Raw {
            provider: 0,
            session: 0,
            content_type: 0,
            accept_type: 0,
            auth_type: 0,
            body_len: 0,
            auth_len: 0,
            opcode: 0,
        }
    }

    /// Serialise the request header and write the corresponding bytes to the given
    /// stream.
    ///
    /// # Errors
    /// - if marshalling the header fails, `ResponseStatus::InvalidEncoding` is returned.
    /// - if writing the header bytes fails, `ResponseStatus::ConnectionError` is returned.
    pub fn write_to_stream<W: Write>(&self, stream: &mut W) -> Result<()> {
        stream.write_all(&bincode::serialize(&MAGIC_NUMBER)?)?;

        stream.write_all(&bincode::serialize(&REQUEST_HDR_SIZE)?)?;

        stream.write_all(&bincode::serialize(&WIRE_PROTOCOL_VERSION_MAJ)?)?;
        stream.write_all(&bincode::serialize(&WIRE_PROTOCOL_VERSION_MIN)?)?;

        stream.write_all(&bincode::serialize(&self)?)?;

        Ok(())
    }

    /// Deserialise a request header from the given stream.
    ///
    /// # Errors
    /// - if either the magic number or the header size are invalid values,
    /// `ResponseStatus::InvalidHeader` is returned.
    /// - if reading the fields after magic number and header size fails,
    /// `ResponseStatus::ConnectionError` is returned
    ///     - the read may fail due to a timeout if not enough bytes are
    ///     sent across
    /// - if the parsed bytes cannot be unmarshalled into the contained fields,
    /// `ResponseStatus::InvalidEncoding` is returned.
    /// - if the wire protocol version used is different than 1.0
    pub fn read_from_stream<R: Read>(mut stream: &mut R) -> Result<Raw> {
        let magic_number = get_from_stream!(stream, u32);
        if magic_number != MAGIC_NUMBER {
            error!(
                "Expected magic number {}, got {}",
                MAGIC_NUMBER, magic_number
            );
            return Err(ResponseStatus::InvalidHeader);
        }

        let hdr_size = get_from_stream!(stream, u16);
        let mut bytes = vec![0_u8; usize::try_from(hdr_size)?];
        stream.read_exact(&mut bytes)?;
        if hdr_size != REQUEST_HDR_SIZE {
            error!(
                "Expected request header size {}, got {}",
                REQUEST_HDR_SIZE, hdr_size
            );
            return Err(ResponseStatus::InvalidHeader);
        }

        let version_maj = bytes.remove(0); // first byte after hdr length is version maj
        let version_min = bytes.remove(0); // second byte after hdr length is version min
        if version_maj != WIRE_PROTOCOL_VERSION_MAJ || version_min != WIRE_PROTOCOL_VERSION_MIN {
            error!(
                "Expected wire protocol version {}.{}, got {}.{} instead",
                WIRE_PROTOCOL_VERSION_MAJ, WIRE_PROTOCOL_VERSION_MIN, version_maj, version_min
            );
            return Err(ResponseStatus::WireProtocolVersionNotSupported);
        }

        Ok(bincode::deserialize(&bytes)?)
    }
}

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
            provider: ProviderID::Core,
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

        let opcode: Opcode = match FromPrimitive::from_u16(header.opcode) {
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
            provider: header.provider as u8,
            session: header.session,
            content_type: header.content_type as u8,
            accept_type: header.accept_type as u8,
            auth_type: header.auth_type as u8,
            body_len: 0,
            auth_len: 0,
            opcode: header.opcode as u16,
        }
    }
}
