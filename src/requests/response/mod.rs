// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Response definition

use super::common::wire_header_1_0::WireHeader as Raw;
use super::request::RequestHeader;
use super::ResponseStatus;
use super::Result;
use log::error;
use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

mod response_body;
mod response_header;

pub use response_body::ResponseBody;
pub use response_header::ResponseHeader;

#[cfg(feature = "testing")]
pub use super::common::wire_header_1_0::WireHeader as RawHeader;

/// Native representation of the response wire format.
#[derive(PartialEq, Debug)]
pub struct Response {
    /// Header of the response, containing the response status.
    pub header: ResponseHeader,
    /// Response body consists of an opaque vector of bytes. Interpretation of said bytes
    /// is deferred to the a converter which can handle the `content_type` defined in the
    /// header.
    pub body: ResponseBody,
}

impl Response {
    /// Create a response with empty header and empty body.
    fn new() -> Response {
        Response {
            header: ResponseHeader::new(),
            body: ResponseBody::new(),
        }
    }

    /// Convert request into an error response with a given `ResponseStatus`.
    ///
    /// The relevant fields in the header are preserved and an empty body is provided
    /// by default.
    pub fn from_request_header(header: RequestHeader, status: ResponseStatus) -> Response {
        let mut response = Response::new();
        response.header = header.into();
        response.header.status = status;

        response
    }

    /// Create an empty response with a specific status.
    pub fn from_status(status: ResponseStatus) -> Response {
        let mut response = Response::new();
        response.header.status = status;

        response
    }

    /// Serialise response and write it to given stream.
    ///
    /// Header is converted to a raw format before serializing.
    ///
    /// # Errors
    /// - if writing any of the subfields (header or body) fails, then
    /// `ResponseStatus::ConnectionError` is returned.
    /// - if encoding any of the fields in the header fails, then
    /// `ResponseStatus::InvalidEncoding` is returned.
    pub fn write_to_stream(self, stream: &mut impl Write) -> Result<()> {
        let mut raw_header: Raw = self.header.into();
        raw_header.body_len = u32::try_from(self.body.len())?;

        raw_header.write_to_stream(stream)?;
        self.body.write_to_stream(stream)?;

        Ok(())
    }

    /// Deserialise response from given stream.
    ///
    /// The `body_len_limit` parameter allows the interface client to reject requests that are
    /// longer than a predefined limit. The length limit is in bytes.
    ///
    /// # Errors
    /// - if reading any of the subfields (header or body) fails, the
    /// corresponding `ResponseStatus` will be returned.
    /// - if the request body size specified in the header is larger than the limit passed as
    /// a parameter, `BodySizeExceedsLimit` will be returned.
    pub fn read_from_stream(stream: &mut impl Read, body_len_limit: usize) -> Result<Response> {
        let raw_header = Raw::read_from_stream(stream)?;
        let body_len = usize::try_from(raw_header.body_len)?;
        if body_len > body_len_limit {
            error!(
                "Request body length ({}) bigger than the limit given ({}).",
                body_len, body_len_limit
            );
            return Err(ResponseStatus::BodySizeExceedsLimit);
        }
        let body = ResponseBody::read_from_stream(stream, body_len)?;

        Ok(Response {
            header: raw_header.try_into()?,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::tests as test_utils;
    use super::super::{BodyType, Opcode, ProviderID, ResponseStatus};
    use super::*;

    #[test]
    fn response_to_stream() {
        let mut mock = test_utils::MockReadWrite { buffer: Vec::new() };
        let response = get_response();

        response
            .write_to_stream(&mut mock)
            .expect("Failed to write response");

        assert_eq!(mock.buffer, get_response_bytes());
    }

    #[test]
    fn stream_to_response() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_response_bytes(),
        };

        let response =
            Response::read_from_stream(&mut mock, 1000).expect("Failed to read response");

        assert_eq!(response, get_response());
    }

    #[test]
    #[should_panic(expected = "Failed to read response")]
    fn failed_read() {
        let mut fail_mock = test_utils::MockFailReadWrite;

        let _ = Response::read_from_stream(&mut fail_mock, 1000).expect("Failed to read response");
    }

    #[test]
    #[should_panic(expected = "Response body too large")]
    fn body_too_large() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_response_bytes(),
        };

        let _ = Response::read_from_stream(&mut mock, 0).expect("Response body too large");
    }

    #[test]
    #[should_panic(expected = "Failed to write response")]
    fn failed_write() {
        let response: Response = get_response();
        let mut fail_mock = test_utils::MockFailReadWrite;

        response
            .write_to_stream(&mut fail_mock)
            .expect("Failed to write response");
    }

    #[test]
    fn wrong_version() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_response_bytes(),
        };
        // Put an invalid version major field.
        mock.buffer[6] = 0xFF;
        // Put an invalid version minor field.
        mock.buffer[7] = 0xFF;

        let response_status =
            Response::read_from_stream(&mut mock, 1000).expect_err("Should have failed.");

        assert_eq!(
            response_status,
            ResponseStatus::WireProtocolVersionNotSupported
        );
    }

    fn get_response() -> Response {
        let body = ResponseBody::from_bytes(vec![0x70, 0x80, 0x90]);
        let header = ResponseHeader {
            provider: ProviderID::Core,
            session: 0x11_22_33_44_55_66_77_88,
            content_type: BodyType::Protobuf,
            opcode: Opcode::Ping,
            status: ResponseStatus::Success,
        };
        Response { header, body }
    }

    fn get_response_bytes() -> Vec<u8> {
        vec![
            0x10, 0xA7, 0xC0, 0x5E, 0x1e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66,
            0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x80, 0x90,
        ]
    }
}
