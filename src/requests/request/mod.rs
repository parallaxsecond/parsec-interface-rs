// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # Request definition
//!
//! A `Request` is to the service to execute one operation.
use super::common::wire_header_1_0::WireHeader as Raw;
use super::response::ResponseHeader;
use crate::requests::{ResponseStatus, Result};
use crate::secrecy::ExposeSecret;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use derivative::Derivative;
use log::error;
use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

mod request_auth;
mod request_body;
mod request_header;

pub use request_auth::RequestAuth;
pub use request_body::RequestBody;
pub use request_header::RequestHeader;

#[cfg(feature = "testing")]
pub use super::common::wire_header_1_0::WireHeader as RawHeader;

/// Representation of the request wire format.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Request {
    /// Request header
    pub header: RequestHeader,
    /// Request body consists of `RequestBody` object holding a collection of bytes.
    /// Interpretation of said bytes is deferred to the a converter which can handle the
    /// `content_type` defined in the header.
    pub body: RequestBody,
    /// Auth field is stored as a `RequestAuth` object. A parser that can handle the `auth_type`
    /// specified in the header is needed to authenticate the request.
    #[derivative(Debug = "ignore")]
    pub auth: RequestAuth,
}

impl Request {
    /// Create a request with "default" header and empty body.
    /// Available for testing purposes only.
    #[cfg(feature = "testing")]
    pub fn new() -> Request {
        Request {
            header: RequestHeader::new(),
            body: RequestBody::new(),
            auth: RequestAuth::new(),
        }
    }

    /// Serialise request and write it to given stream.
    ///
    /// Request header is first converted to its raw format before serialization.
    ///
    /// # Errors
    /// - if an IO operation fails while writing any of the subfields of the request,
    /// `ResponseStatus::ConnectionError` is returned.
    /// - if encoding any of the fields in the header fails, `ResponseStatus::InvalidEncoding`
    /// is returned.
    pub fn write_to_stream(self, stream: &mut impl Write) -> Result<()> {
        let mut raw_header: Raw = self.header.into();
        raw_header.body_len = u32::try_from(self.body.len())?;
        raw_header.auth_len = u16::try_from(self.auth.buffer.expose_secret().len())?;
        raw_header.write_to_stream(stream)?;

        self.body.write_to_stream(stream)?;
        self.auth.write_to_stream(stream)?;

        Ok(())
    }

    /// Deserialise request from given stream.
    ///
    /// Request header is parsed from its raw form, ensuring that all fields are valid.
    /// The `body_len_limit` parameter allows the interface client to reject requests that are
    /// longer than a predefined limit. The length limit is in bytes.
    ///
    /// # Errors
    /// - if reading any of the subfields (header, body or auth) fails, the corresponding
    /// `ResponseStatus` will be returned.
    /// - if the request body size specified in the header is larger than the limit passed as
    /// a parameter, `BodySizeExceedsLimit` will be returned.
    pub fn read_from_stream(stream: &mut impl Read, body_len_limit: usize) -> Result<Request> {
        let raw_header = Raw::read_from_stream(stream)?;
        let body_len = usize::try_from(raw_header.body_len)?;
        if body_len > body_len_limit {
            error!(
                "Request body length ({}) bigger than the limit given ({}).",
                body_len, body_len_limit
            );
            return Err(ResponseStatus::BodySizeExceedsLimit);
        }
        let body = RequestBody::read_from_stream(stream, body_len)?;
        let auth = RequestAuth::read_from_stream(stream, usize::try_from(raw_header.auth_len)?)?;

        Ok(Request {
            header: raw_header.try_into()?,
            body,
            auth,
        })
    }
}

#[cfg(feature = "testing")]
impl Default for Request {
    fn default() -> Request {
        Request::new()
    }
}

/// Conversion from `RequestHeader` to `ResponseHeader` is useful for
/// when reversing data flow, from handling a request to handling a response.
impl From<RequestHeader> for ResponseHeader {
    fn from(req_hdr: RequestHeader) -> ResponseHeader {
        ResponseHeader {
            provider: req_hdr.provider,
            session: req_hdr.session,
            content_type: req_hdr.accept_type,
            opcode: req_hdr.opcode,
            status: ResponseStatus::Success,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::tests as test_utils;
    use super::super::{AuthType, BodyType, Opcode, ProviderID, ResponseStatus};
    use super::*;

    #[test]
    fn request_to_stream() {
        let mut mock = test_utils::MockReadWrite { buffer: Vec::new() };
        let request = get_request();

        request
            .write_to_stream(&mut mock)
            .expect("Failed to write request");

        assert_eq!(mock.buffer, get_request_bytes());
    }

    #[test]
    fn stream_to_request() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_request_bytes(),
        };

        let request = Request::read_from_stream(&mut mock, 1000).expect("Failed to read request");
        let exp_req = get_request();

        assert_eq!(request.header, exp_req.header);
        assert_eq!(request.body, exp_req.body);
        assert_eq!(
            request.auth.buffer.expose_secret(),
            exp_req.auth.buffer.expose_secret()
        );
    }

    #[test]
    #[should_panic(expected = "Failed to read request")]
    fn failed_read() {
        let mut fail_mock = test_utils::MockFailReadWrite;

        let _ = Request::read_from_stream(&mut fail_mock, 1000).expect("Failed to read request");
    }

    #[test]
    #[should_panic(expected = "Request body too large")]
    fn body_too_large() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_request_bytes(),
        };

        let _ = Request::read_from_stream(&mut mock, 0).expect("Request body too large");
    }

    #[test]
    #[should_panic(expected = "Failed to write request")]
    fn failed_write() {
        let request: Request = get_request();
        let mut fail_mock = test_utils::MockFailReadWrite;

        request
            .write_to_stream(&mut fail_mock)
            .expect("Failed to write request");
    }

    #[test]
    fn req_hdr_to_resp_hdr() {
        let req_hdr = get_request().header;
        let resp_hdr: ResponseHeader = req_hdr.into();

        let mut resp_hdr_exp = ResponseHeader::new();
        resp_hdr_exp.provider = ProviderID::Core;
        resp_hdr_exp.session = 0x11_22_33_44_55_66_77_88;
        resp_hdr_exp.content_type = BodyType::Protobuf;
        resp_hdr_exp.opcode = Opcode::Ping;
        resp_hdr_exp.status = ResponseStatus::Success;

        assert_eq!(resp_hdr, resp_hdr_exp);
    }

    #[test]
    fn wrong_version() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_request_bytes(),
        };
        // Put an invalid version major field.
        mock.buffer[6] = 0xFF;
        // Put an invalid version minor field.
        mock.buffer[7] = 0xFF;

        let response_status =
            Request::read_from_stream(&mut mock, 1000).expect_err("Should have failed.");

        assert_eq!(
            response_status,
            ResponseStatus::WireProtocolVersionNotSupported
        );
    }

    fn get_request() -> Request {
        let body = RequestBody::from_bytes(vec![0x70, 0x80, 0x90]);
        let auth = RequestAuth::new(vec![0xa0, 0xb0, 0xc0]);
        let header = RequestHeader {
            provider: ProviderID::Core,
            session: 0x11_22_33_44_55_66_77_88,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            auth_type: AuthType::Direct,
            opcode: Opcode::Ping,
        };
        Request { header, body, auth }
    }

    fn get_request_bytes() -> Vec<u8> {
        vec![
            0x10, 0xA7, 0xC0, 0x5E, 0x1e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66,
            0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
        ]
    }
}
