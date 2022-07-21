// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! This module defines and implements the raw wire protocol header frame for
//! version 1.0 of the protocol.
use crate::requests::common::MAGIC_NUMBER;
use crate::requests::{ResponseStatus, Result};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use bincode::Options;
use log::error;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{Read, Write};

const WIRE_PROTOCOL_VERSION_MAJ: u8 = 1;
const WIRE_PROTOCOL_VERSION_MIN: u8 = 0;

const REQUEST_HDR_SIZE: u16 = 30;

/// Raw representation of a common request/response header, as defined for the wire format.
///
/// Serialisation and deserialisation are handled by `serde`, also in tune with the
/// wire format (i.e. little-endian, native encoding).
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct WireHeader {
    /// Implementation-defined flags. Not used in Parsec currently. Must be present, but must be zero.
    pub flags: u16,
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
    pub opcode: u32,
    /// Response status of the request.
    pub status: u16,
    /// Reserved byte. Currently unused. Must be present. Must be zero.
    pub reserved1: u8,
    /// Reserved byte. Currently unused. Must be present. Must be zero.
    pub reserved2: u8,
}

impl WireHeader {
    /// Create a new raw wire header.
    ///
    /// For use in testing only.
    #[cfg(feature = "testing")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> WireHeader {
        WireHeader {
            flags: 0,
            provider: 0,
            session: 0,
            content_type: 0,
            accept_type: 0,
            auth_type: 0,
            body_len: 0,
            auth_len: 0,
            opcode: 0,
            status: 0,
            reserved1: 0,
            reserved2: 0,
        }
    }

    /// Serialise the request header and write the corresponding bytes to the given
    /// stream.
    ///
    /// # Errors
    /// - if marshalling the header fails, `ResponseStatus::InvalidEncoding` is returned.
    /// - if writing the header bytes fails, `ResponseStatus::ConnectionError` is returned.
    pub fn write_to_stream<W: Write>(&self, stream: &mut W) -> Result<()> {
        let serdes = bincode::DefaultOptions::new()
            .with_little_endian()
            .with_fixint_encoding();

        stream.write_all(&serdes.serialize(&MAGIC_NUMBER)?)?;

        stream.write_all(&serdes.serialize(&REQUEST_HDR_SIZE)?)?;

        stream.write_all(&serdes.serialize(&WIRE_PROTOCOL_VERSION_MAJ)?)?;
        stream.write_all(&serdes.serialize(&WIRE_PROTOCOL_VERSION_MIN)?)?;

        stream.write_all(&serdes.serialize(&self)?)?;

        Ok(())
    }

    /// Deserialise a request header from the given stream.
    ///
    /// # Errors
    /// - if either the magic number, the header size or the reserved fields
    /// are invalid values, `ResponseStatus::InvalidHeader` is returned.
    /// - if reading the fields after magic number and header size fails,
    /// `ResponseStatus::ConnectionError` is returned
    ///     - the read may fail due to a timeout if not enough bytes are
    ///     sent across
    /// - if the parsed bytes cannot be unmarshalled into the contained fields,
    /// `ResponseStatus::InvalidEncoding` is returned.
    /// - if the wire protocol version used is different than 1.0
    pub fn read_from_stream<R: Read>(mut stream: &mut R) -> Result<WireHeader> {
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

        let serdes = bincode::DefaultOptions::new()
            .with_little_endian()
            .with_fixint_encoding();
        let wire_header: WireHeader = serdes.deserialize(&bytes)?;

        if wire_header.reserved1 != 0x00 || wire_header.reserved2 != 0x00 {
            Err(ResponseStatus::InvalidHeader)
        } else {
            Ok(wire_header)
        }
    }
}
