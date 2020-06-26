// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # Protobuf converter
//!
//! This module exposes the `ProtobufConverter` struct that implements the `Convert` trait.
mod convert_psa_algorithm;
mod convert_ping;
mod convert_psa_generate_key;
mod convert_psa_key_attributes;
mod convert_psa_import_key;
mod convert_psa_export_public_key;
mod convert_psa_destroy_key;
mod convert_psa_sign_hash;
mod convert_psa_verify_hash;
mod convert_list_providers;
mod convert_list_opcodes;

#[rustfmt::skip]
#[allow(unused_qualifications, missing_copy_implementations, clippy::pedantic, clippy::module_inception)]
mod generated_ops;

use crate::operations::{Convert, NativeOperation, NativeResult};
use crate::requests::{
    request::RequestBody, response::ResponseBody, BodyType, Opcode, ResponseStatus, Result,
};
use generated_ops::list_opcodes as list_opcodes_proto;
use generated_ops::list_providers as list_providers_proto;
use generated_ops::ping as ping_proto;
use generated_ops::psa_destroy_key as psa_destroy_key_proto;
use generated_ops::psa_export_public_key as psa_export_public_key_proto;
use generated_ops::psa_generate_key as psa_generate_key_proto;
use generated_ops::psa_import_key as psa_import_key_proto;
use generated_ops::psa_sign_hash as psa_sign_hash_proto;
use generated_ops::psa_verify_hash as psa_verify_hash_proto;
use generated_ops::ClearProtoMessage;
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
        let mut proto: $proto_type = $native_msg.try_into()?;
        let mut bytes = Vec::new();
        if proto.encode(&mut bytes).is_err() {
            proto.clear_message();
            return Err(ResponseStatus::SerializingBodyFailed);
        }
        proto.clear_message();
        bytes
    }};
}

/// Implementation for a converter between protobuf-encoded bodies and native
/// objects.
#[derive(Copy, Clone, Debug)]
pub struct ProtobufConverter;

impl Convert for ProtobufConverter {
    fn body_type(&self) -> BodyType {
        BodyType::Protobuf
    }

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
            Opcode::PsaGenerateKey => Ok(NativeOperation::PsaGenerateKey(wire_to_native!(
                body.bytes(),
                psa_generate_key_proto::Operation
            ))),
            Opcode::PsaImportKey => Ok(NativeOperation::PsaImportKey(wire_to_native!(
                body.bytes(),
                psa_import_key_proto::Operation
            ))),
            Opcode::PsaExportPublicKey => Ok(NativeOperation::PsaExportPublicKey(wire_to_native!(
                body.bytes(),
                psa_export_public_key_proto::Operation
            ))),
            Opcode::PsaDestroyKey => Ok(NativeOperation::PsaDestroyKey(wire_to_native!(
                body.bytes(),
                psa_destroy_key_proto::Operation
            ))),
            Opcode::PsaSignHash => Ok(NativeOperation::PsaSignHash(wire_to_native!(
                body.bytes(),
                psa_sign_hash_proto::Operation
            ))),
            Opcode::PsaVerifyHash => Ok(NativeOperation::PsaVerifyHash(wire_to_native!(
                body.bytes(),
                psa_verify_hash_proto::Operation
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
            NativeOperation::PsaGenerateKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_generate_key_proto::Operation),
            )),
            NativeOperation::PsaImportKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_import_key_proto::Operation),
            )),
            NativeOperation::PsaExportPublicKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_export_public_key_proto::Operation),
            )),
            NativeOperation::PsaDestroyKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_destroy_key_proto::Operation),
            )),
            NativeOperation::PsaSignHash(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_sign_hash_proto::Operation),
            )),
            NativeOperation::PsaVerifyHash(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, psa_verify_hash_proto::Operation),
            )),
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
            Opcode::PsaGenerateKey => Ok(NativeResult::PsaGenerateKey(wire_to_native!(
                body.bytes(),
                psa_generate_key_proto::Result
            ))),
            Opcode::PsaImportKey => Ok(NativeResult::PsaImportKey(wire_to_native!(
                body.bytes(),
                psa_import_key_proto::Result
            ))),
            Opcode::PsaExportPublicKey => Ok(NativeResult::PsaExportPublicKey(wire_to_native!(
                body.bytes(),
                psa_export_public_key_proto::Result
            ))),
            Opcode::PsaDestroyKey => Ok(NativeResult::PsaDestroyKey(wire_to_native!(
                body.bytes(),
                psa_destroy_key_proto::Result
            ))),
            Opcode::PsaSignHash => Ok(NativeResult::PsaSignHash(wire_to_native!(
                body.bytes(),
                psa_sign_hash_proto::Result
            ))),
            Opcode::PsaVerifyHash => Ok(NativeResult::PsaVerifyHash(wire_to_native!(
                body.bytes(),
                psa_verify_hash_proto::Result
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
            NativeResult::PsaGenerateKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_generate_key_proto::Result
            ))),
            NativeResult::PsaImportKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_import_key_proto::Result
            ))),
            NativeResult::PsaExportPublicKey(result) => Ok(ResponseBody::from_bytes(
                native_to_wire!(result, psa_export_public_key_proto::Result),
            )),
            NativeResult::PsaDestroyKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_destroy_key_proto::Result
            ))),
            NativeResult::PsaSignHash(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_sign_hash_proto::Result
            ))),
            NativeResult::PsaVerifyHash(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                psa_verify_hash_proto::Result
            ))),
        }
    }
}
