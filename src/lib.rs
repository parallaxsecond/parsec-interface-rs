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
#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    legacy_directory_ownership,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    plugin_as_library,
    private_in_public,
    safe_extern_statics,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    //TODO: activate this!
    //missing_docs,
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
//! # Parsec Rust Interface
//!
//! The Parsec Rust Interface provides methods to communicate easily with the Parsec service using
//! the [wire protocol](https://github.com/docker/parsec/blob/master/docs/wire_protocol.md).
//!
//! ## For the Parsec service
//!
//! This library is used by the Parsec service to:
//! * read from a stream a `Request` sent to the service with the `read_from_stream` method
//! * use the `body_to_operation` method of the `Convert` trait on a converter to parse the request
//! body into a `NativeOperation`
//!
//! execute the operation to yield a `NativeResult` and:
//! * use the `result_to_body` method to serialize the `NativeResult`
//! * create a `Response` containing the result as its body and write it back to the stream  with
//! the `write_to_stream` method.
//!
//! ### Example
//!
//!```no_run
//!use std::os::unix::net::UnixStream;
//!use parsec_interface::operations::{Convert, NativeResult};
//!use parsec_interface::requests::{Request, Response};
//!use parsec_interface::operations_protobuf::ProtobufConverter;
//!use parsec_interface::operations::ResultCreateKey;
//!
//!const MAX_BODY_LENGTH: usize = 2048;
//!
//!let mut stream = UnixStream::connect("socket_path").unwrap();
//!let converter = ProtobufConverter {};
//!let request = Request::read_from_stream(&mut stream, MAX_BODY_LENGTH).unwrap();
//!let operation = converter.body_to_operation(request.body, request.header.opcode).unwrap();
//!
//!// Deal with the operation to get a `NativeResult`
//!let result = NativeResult::CreateKey(ResultCreateKey {});
//!let result_body = converter.result_to_body(result).unwrap();
//!let response = Response {
//!    header: request.header.into(),
//!    body: result_body,
//!};
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
//! and after the operation has been executed by the Parsec service:
//! * read from a stream the `Response` from the service with the `read_from_stream` method
//! * use the `body_to_result` method to parse the result body into a `NativeResult`
//!
//! See the [Parsec Test client](https://github.com/docker/parsec-client-test) as an example of a
//! Rust client.
//!
//! ### Example
//!
//!```no_run
//!use std::os::unix::net::UnixStream;
//!use parsec_interface::operations::{Convert, NativeOperation};
//!use parsec_interface::requests::{Request, Response, ProviderID, BodyType, AuthType, Opcode};
//!use parsec_interface::requests::request::{RequestHeader, RequestAuth};
//!use parsec_interface::operations_protobuf::ProtobufConverter;
//!use parsec_interface::operations::OpPing;
//!
//!const MAX_BODY_LENGTH: usize = 2048;
//!
//!let mut stream = UnixStream::connect("socket_path").unwrap();
//!let converter = ProtobufConverter {};
//!let operation = NativeOperation::Ping(OpPing {});
//!let request = Request {
//!    header: RequestHeader {
//!        version_maj: 0,
//!        version_min: 0,
//!        provider: ProviderID::CoreProvider,
//!        session: 0,
//!        content_type: BodyType::Protobuf,
//!        accept_type: BodyType::Protobuf,
//!        auth_type: AuthType::Simple,
//!        opcode: Opcode::Ping,
//!    },
//!    body: converter.operation_to_body(operation).unwrap(),
//!    auth: RequestAuth::from_bytes(Vec::new()),
//!};
//!request.write_to_stream(&mut stream).unwrap();
//!
//!// Wait for the service to execute the operation
//!let response = Response::read_from_stream(&mut stream, MAX_BODY_LENGTH).unwrap();
//!let result = converter.body_to_result(response.body, response.header.opcode).unwrap();
//!```

pub mod operations;
pub mod operations_protobuf;
pub mod requests;
