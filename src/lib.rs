// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]
// This crate declares deprecated values for legacy reasons.
#![allow(deprecated)]
//! # Parsec Rust Interface
//!
//! The Parsec Rust Interface provides methods to communicate easily with the Parsec service using
//! the [wire protocol](https://github.com/docker/parsec/blob/master/docs/wire_protocol.md) and the
//! [operation
//! contracts](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/index.html).
//!
//! ## For the Parsec service
//!
//! This library is used by the Parsec service to:
//! * read from a stream a `Request` sent to the service with the `read_from_stream` method
//! * use the `body_to_operation` method of the `Convert` trait on a converter to parse the request
//! body into a `NativeOperation`
//!
//!```
//!# use std::io::Read;
//!#
//!# pub struct MockRead {
//!#    pub buffer: Vec<u8>,
//!# }
//!#
//!# impl Read for MockRead {
//!#     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//!#         for val in buf.iter_mut() {
//!#             *val = self.buffer.remove(0);
//!#         }
//!#
//!#         Ok(buf.len())
//!#     }
//!# }
//!#
//!# let mut stream = MockRead {
//!#     buffer: vec![
//!#         0x10, 0xA7, 0xC0, 0x5E, 0x1e, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//!#         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0,
//!#         0x0, 0x0, 0x0, 0x0, 0x0, 0x72, 0x6F, 0x6F, 0x74
//!#     ]
//!# };
//!use parsec_interface::operations::{Convert, NativeOperation};
//!use parsec_interface::requests::Request;
//!use parsec_interface::operations_protobuf::ProtobufConverter;
//!
//!let converter = ProtobufConverter {};
//!// stream is a Read object
//!let request = Request::read_from_stream(&mut stream, 2048).unwrap();
//!let operation: NativeOperation = converter
//!                                 .body_to_operation(request.body, request.header.opcode)
//!                                 .unwrap();
//!```
//!
//! The service can now execute the operation to yield a `NativeResult` and:
//! * use the `result_to_body` method to serialize the `NativeResult`
//! * create a `Response` containing the result as its body and write it back to the stream  with
//! the `write_to_stream` method.
//!
//!```
//!# use std::io::Write;
//!#
//!# pub struct MockWrite {
//!#     pub buffer: Vec<u8>,
//!# }
//!#
//!# impl Write for MockWrite {
//!#     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//!#         for val in buf.iter() {
//!#             self.buffer.push(*val);
//!#         }
//!#         Ok(buf.len())
//!#     }
//!#
//!#     fn flush(&mut self) -> std::io::Result<()> {
//!#         Ok(())
//!#     }
//!# }
//!# let mut stream = MockWrite { buffer: Vec::new() };
//!use parsec_interface::operations::{Convert, NativeResult, psa_generate_key::Result};
//!use parsec_interface::requests::{ProviderID, Opcode, BodyType, Response, ResponseStatus};
//!use parsec_interface::requests::response::ResponseHeader;
//!use parsec_interface::operations_protobuf::ProtobufConverter;
//!
//!let converter = ProtobufConverter {};
//!let result = NativeResult::PsaGenerateKey(Result {});
//!let result_body = converter.result_to_body(result).unwrap();
//!let response = Response {
//!    header: ResponseHeader {
//!        provider: ProviderID::new(1),
//!        session: 0,
//!        content_type: BodyType::Protobuf,
//!        opcode: Opcode::PsaGenerateKey,
//!        status: ResponseStatus::Success,
//!    },
//!    body: result_body,
//!};
//!// stream is a Write object
//!response.write_to_stream(&mut stream).unwrap();
//!```
//!
//! ## For the Parsec Rust clients
//!
//! This library is used by the Parsec Rust clients to:
//! * use the `operation_to_body` method to serialize the `NativeOperation` to be sent as body of a
//! `Request`
//! * write it to the stream with the `write_to_stream` method.
//!
//!```
//!# use std::io::Write;
//!#
//!# pub struct MockWrite {
//!#     pub buffer: Vec<u8>,
//!# }
//!#
//!# impl Write for MockWrite {
//!#     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//!#         for val in buf.iter() {
//!#             self.buffer.push(*val);
//!#         }
//!#         Ok(buf.len())
//!#     }

//!#     fn flush(&mut self) -> std::io::Result<()> {
//!#         Ok(())
//!#     }
//!# }
//!#
//!# let mut stream = MockWrite { buffer: Vec::new() };
//!use parsec_interface::operations::{Convert, NativeOperation};
//!use parsec_interface::requests::{Request, ProviderID, BodyType, AuthType, Opcode};
//!use parsec_interface::requests::request::{RequestHeader, RequestAuth};
//!use parsec_interface::operations_protobuf::ProtobufConverter;
//!use parsec_interface::operations::ping::Operation;
//!
//!let converter = ProtobufConverter {};
//!let operation = NativeOperation::Ping(Operation {});
//!let request = Request {
//!    header: RequestHeader {
//!        provider: ProviderID::core(),
//!        session: 0,
//!        content_type: BodyType::Protobuf,
//!        accept_type: BodyType::Protobuf,
//!        auth_type: AuthType::Direct,
//!        opcode: Opcode::Ping,
//!    },
//!    body: converter.operation_to_body(operation).unwrap(),
//!    auth: RequestAuth::new(Vec::from("root")),
//!};
//!// stream is a Write object
//!request.write_to_stream(&mut stream).unwrap();
//!```
//!
//! After the operation has been executed by the Parsec service:
//! * read from a stream the `Response` from the service with the `read_from_stream` method
//! * use the `body_to_result` method to parse the result body into a `NativeResult`
//!
//!```
//!# use std::io::Read;
//!#
//!# pub struct MockRead {
//!#     pub buffer: Vec<u8>,
//!# }
//!#
//!# impl Read for MockRead {
//!#     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//!#         for val in buf.iter_mut() {
//!#             *val = self.buffer.remove(0);
//!#         }
//!#
//!#         Ok(buf.len())
//!#     }
//!# }
//!#
//!# let mut stream = MockRead {
//!#     buffer: vec![
//!#         0x10, 0xA7, 0xC0, 0x5E, 0x1e, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
//!#         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0,
//!#         0x0, 0x0, 0x0, 0x0
//!#     ]
//!# };
//!use parsec_interface::operations::{Convert, NativeResult};
//!use parsec_interface::requests::Response;
//!use parsec_interface::operations_protobuf::ProtobufConverter;
//!
//!let converter = ProtobufConverter {};
//!// stream is a Read object
//!let response = Response::read_from_stream(&mut stream, 2048).unwrap();
//!let result: NativeResult = converter
//!                           .body_to_result(response.body, response.header.opcode)
//!                           .unwrap();
//!```
//!
//! See the [Parsec Test client](https://github.com/parallaxsecond/parsec-client-test) as an example
//! of a Rust client.

pub mod operations;
pub mod operations_protobuf;
pub mod requests;

/// Module providing access to secret-wrapping functionality.
pub use secrecy;
