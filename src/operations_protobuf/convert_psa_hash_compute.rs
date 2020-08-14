// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::convert_psa_algorithm;
use super::generated_ops::psa_hash_compute::{Operation as OperationProto, Result as ResultProto};
use crate::operations::psa_hash_compute::{Operation, Result};
use crate::requests::ResponseStatus;
use std::convert::TryFrom;

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        let input = proto_op.input.into();
        Ok(Operation {
            alg: convert_psa_algorithm::i32_to_hash(proto_op.alg)?,
            input,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(OperationProto {
            input: op.input.to_vec(),
            alg: convert_psa_algorithm::hash_to_i32(op.alg),
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_result: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {
            hash: proto_result.hash.into(),
        })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(ResultProto {
            hash: result.hash.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::psa_algorithm as algorithm_proto;
    use super::super::generated_ops::psa_hash_compute::{
        Operation as OperationProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::psa_algorithm::Hash;
    use crate::operations::psa_hash_compute::{Operation, Result};
    use crate::operations::{NativeOperation, NativeResult};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn hash_compute_proto_to_op() {
        let mut proto: OperationProto = Default::default();
        let input = vec![0x11, 0x22, 0x33];
        proto.input = input.clone();
        proto.alg = algorithm_proto::algorithm::Hash::Sha256.into();

        let op: Operation = proto.try_into().expect("Failed to convert");

        assert_eq!(op.input, input.into());
        assert_eq!(op.alg, Hash::Sha256);
    }

    #[test]
    fn hash_compute_op_to_proto() {
        let input = vec![0x11, 0x22, 0x33];
        let alg = Hash::Sha256;

        let op = Operation {
            alg,
            input: input.clone().into(),
        };

        let proto: OperationProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.input, input);
    }

    #[test]
    fn hash_compute_proto_to_resp() {
        let mut proto: ResultProto = Default::default();
        let hash = vec![0x11, 0x22, 0x33];
        proto.hash = hash.clone();

        let result: Result = proto.try_into().expect("Failed to convert");

        assert_eq!(result.hash, hash.into());
    }

    #[test]
    fn hash_compute_resp_to_proto() {
        let hash = vec![0x11, 0x22, 0x33];
        let result = Result {
            hash: hash.clone().into(),
        };

        let proto: ResultProto = result.try_into().expect("Failed to convert");

        assert_eq!(proto.hash, hash);
    }

    #[test]
    fn op_hash_compute_sign_e2e() {
        let op = Operation {
            input: vec![0x11, 0x22, 0x33].into(),
            alg: Hash::Sha256,
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::PsaHashCompute(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(body, Opcode::PsaHashCompute)
            .is_ok());
    }

    #[test]
    fn resp_hash_compute_sign_e2e() {
        let result = Result {
            hash: vec![0x11, 0x22, 0x33].into(),
        };
        let body = CONVERTER
            .result_to_body(NativeResult::PsaHashCompute(result))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_result(body, Opcode::PsaHashCompute)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::PsaHashCompute)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::PsaHashCompute)
            .is_err());
    }
}
