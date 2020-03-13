// Copyright (c) 2019-2020, Arm Limited, All Rights Reserved
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
//! # Protobuf converter
//!
//! This module exposes the `ProtobufConverter` struct that implements the `Convert` trait.
mod convert_algorithm;
mod convert_ping;
mod convert_generate_key;
mod convert_key_attributes;
mod convert_import_key;
mod convert_export_public_key;
mod convert_destroy_key;
mod convert_sign_hash;
mod convert_verify_hash;
mod convert_list_providers;
mod convert_list_opcodes;

#[rustfmt::skip]
#[allow(unused_qualifications, missing_copy_implementations, clippy::pedantic, clippy::module_inception)]
mod generated_ops {
    // Include the Rust generated file in its own module.
    macro_rules! include_protobuf_as_module {
        ($name:ident) => {
            pub mod $name {
                // The generated Rust file is in OUT_DIR, named $name.rs
                include!(concat!(env!("OUT_DIR"), "/", stringify!($name), ".rs"));
            }
        };
    }

    include_protobuf_as_module!(sign_hash);
    include_protobuf_as_module!(verify_hash);
    include_protobuf_as_module!(generate_key);
    include_protobuf_as_module!(destroy_key);
    include_protobuf_as_module!(export_public_key);
    include_protobuf_as_module!(import_key);
    include_protobuf_as_module!(list_opcodes);
    include_protobuf_as_module!(list_providers);
    include_protobuf_as_module!(ping);
    include_protobuf_as_module!(key_attributes);
    include_protobuf_as_module!(algorithm);
}

use crate::operations::{Convert, NativeOperation, NativeResult};
use crate::requests::{
    request::RequestBody, response::ResponseBody, Opcode, ResponseStatus, Result,
};
use generated_ops::destroy_key as destroy_key_proto;
use generated_ops::export_public_key as export_public_key_proto;
use generated_ops::generate_key as generate_key_proto;
use generated_ops::import_key as import_key_proto;
use generated_ops::list_opcodes as list_opcodes_proto;
use generated_ops::list_providers as list_providers_proto;
use generated_ops::ping as ping_proto;
use generated_ops::sign_hash as sign_hash_proto;
use generated_ops::verify_hash as verify_hash_proto;
use prost::Message;
use std::convert::TryInto;

macro_rules! wire_to_native {
    ($body:expr, $proto_type:ty) => {{
        let mut proto: $proto_type = Default::default();
        if proto.merge($body).is_err() {
            return Err(ResponseStatus::DeserializingBodyFailed);
        }
        proto.try_into()?
    }};
}

macro_rules! native_to_wire {
    ($native_msg:expr, $proto_type:ty) => {{
        let proto: $proto_type = $native_msg.try_into()?;
        let mut bytes = Vec::new();
        if proto.encode(&mut bytes).is_err() {
            return Err(ResponseStatus::SerializingBodyFailed);
        }
        bytes
    }};
}

/// Implementation for a converter between protobuf-encoded bodies and native
/// objects.
#[derive(Copy, Clone, Debug)]
pub struct ProtobufConverter;

impl Convert for ProtobufConverter {
    fn body_to_operation(&self, body: RequestBody, opcode: Opcode) -> Result<NativeOperation> {
        match opcode {
            Opcode::ListProviders => Ok(NativeOperation::ListProviders(wire_to_native!(
                body.bytes(),
                list_providers_proto::Operation
            ))),
            Opcode::ListOpcodes => Ok(NativeOperation::ListOpcodes(wire_to_native!(
                body.bytes(),
                list_opcodes_proto::Operation
            ))),
            Opcode::Ping => Ok(NativeOperation::Ping(wire_to_native!(
                body.bytes(),
                ping_proto::Operation
            ))),
            Opcode::GenerateKey => Ok(NativeOperation::GenerateKey(wire_to_native!(
                body.bytes(),
                generate_key_proto::Operation
            ))),
            Opcode::ImportKey => Ok(NativeOperation::ImportKey(wire_to_native!(
                body.bytes(),
                import_key_proto::Operation
            ))),
            Opcode::ExportPublicKey => Ok(NativeOperation::ExportPublicKey(wire_to_native!(
                body.bytes(),
                export_public_key_proto::Operation
            ))),
            Opcode::DestroyKey => Ok(NativeOperation::DestroyKey(wire_to_native!(
                body.bytes(),
                destroy_key_proto::Operation
            ))),
            Opcode::SignHash => Ok(NativeOperation::SignHash(wire_to_native!(
                body.bytes(),
                sign_hash_proto::Operation
            ))),
            Opcode::VerifyHash => Ok(NativeOperation::VerifyHash(wire_to_native!(
                body.bytes(),
                verify_hash_proto::Operation
            ))),
        }
    }

    fn operation_to_body(&self, operation: NativeOperation) -> Result<RequestBody> {
        match operation {
            NativeOperation::ListProviders(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, list_providers_proto::Operation),
            )),
            NativeOperation::ListOpcodes(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, list_opcodes_proto::Operation),
            )),
            NativeOperation::Ping(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                ping_proto::Operation
            ))),
            NativeOperation::GenerateKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, generate_key_proto::Operation),
            )),
            NativeOperation::ImportKey(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                import_key_proto::Operation
            ))),
            NativeOperation::ExportPublicKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, export_public_key_proto::Operation),
            )),
            NativeOperation::DestroyKey(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                destroy_key_proto::Operation
            ))),
            NativeOperation::SignHash(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                sign_hash_proto::Operation
            ))),
            NativeOperation::VerifyHash(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                verify_hash_proto::Operation
            ))),
        }
    }

    fn body_to_result(&self, body: ResponseBody, opcode: Opcode) -> Result<NativeResult> {
        match opcode {
            Opcode::ListProviders => Ok(NativeResult::ListProviders(wire_to_native!(
                body.bytes(),
                list_providers_proto::Result
            ))),
            Opcode::ListOpcodes => Ok(NativeResult::ListOpcodes(wire_to_native!(
                body.bytes(),
                list_opcodes_proto::Result
            ))),
            Opcode::Ping => Ok(NativeResult::Ping(wire_to_native!(
                body.bytes(),
                ping_proto::Result
            ))),
            Opcode::GenerateKey => Ok(NativeResult::GenerateKey(wire_to_native!(
                body.bytes(),
                generate_key_proto::Result
            ))),
            Opcode::ImportKey => Ok(NativeResult::ImportKey(wire_to_native!(
                body.bytes(),
                import_key_proto::Result
            ))),
            Opcode::ExportPublicKey => Ok(NativeResult::ExportPublicKey(wire_to_native!(
                body.bytes(),
                export_public_key_proto::Result
            ))),
            Opcode::DestroyKey => Ok(NativeResult::DestroyKey(wire_to_native!(
                body.bytes(),
                destroy_key_proto::Result
            ))),
            Opcode::SignHash => Ok(NativeResult::SignHash(wire_to_native!(
                body.bytes(),
                sign_hash_proto::Result
            ))),
            Opcode::VerifyHash => Ok(NativeResult::VerifyHash(wire_to_native!(
                body.bytes(),
                verify_hash_proto::Result
            ))),
        }
    }

    fn result_to_body(&self, result: NativeResult) -> Result<ResponseBody> {
        match result {
            NativeResult::ListProviders(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                list_providers_proto::Result
            ))),
            NativeResult::ListOpcodes(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                list_opcodes_proto::Result
            ))),
            NativeResult::Ping(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ping_proto::Result
            ))),
            NativeResult::GenerateKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                generate_key_proto::Result
            ))),
            NativeResult::ImportKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                import_key_proto::Result
            ))),
            NativeResult::ExportPublicKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                export_public_key_proto::Result
            ))),
            NativeResult::DestroyKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                destroy_key_proto::Result
            ))),
            NativeResult::SignHash(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                sign_hash_proto::Result
            ))),
            NativeResult::VerifyHash(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                verify_hash_proto::Result
            ))),
        }
    }
}
