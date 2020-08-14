// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::convert_psa_algorithm;
use super::generated_ops::psa_hash_compare::{Operation as OperationProto, Result as ResultProto};
use crate::operations::psa_hash_compare::{Operation, Result};
use crate::requests::ResponseStatus;
use std::convert::TryFrom;

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        let hash = proto_op.hash.into();
        let input = proto_op.input.into();
        Ok(Operation {
            alg: convert_psa_algorithm::i32_to_hash(proto_op.alg)?,
            input,
            hash,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(OperationProto {
            hash: op.hash.to_vec(),
            input: op.input.to_vec(),
            alg: convert_psa_algorithm::hash_to_i32(op.alg),
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(_proto_result: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(_result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(ResultProto {})
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::psa_algorithm as algorithm_proto;
    use super::super::generated_ops::psa_hash_compare::{
        Operation as OperationProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::psa_algorithm::Hash;
    use crate::operations::psa_hash_compare::{Operation, Result};
    use crate::operations::NativeOperation;
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;
    use zeroize::Zeroizing;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn hash_compare_proto_to_op() {
        let mut proto: OperationProto = Default::default();
        let input = vec![0x11, 0x22, 0x33];
        let hash = vec![0x44, 0x55, 0x66];
        proto.input = input.clone();
        proto.hash = hash.clone();
        proto.alg = algorithm_proto::algorithm::Hash::Sha256.into();

        let op: Operation = proto.try_into().expect("Failed to convert");

        assert_eq!(op.input, input.into());
        assert_eq!(op.hash, hash.into());
        assert_eq!(op.alg, Hash::Sha256);
    }

    #[test]
    fn hash_compare_op_to_proto() {
        let input = vec![0x11, 0x22, 0x33];
        let hash = vec![0x44, 0x55, 0x66];
        let alg = Hash::Sha256;

        let op = Operation {
            alg,
            input: input.clone().into(),
            hash: hash.clone().into(),
        };

        let proto: OperationProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.input, input);
        assert_eq!(proto.hash, hash);
    }

    #[test]
    fn hash_compare_proto_to_resp() {
        let proto = ResultProto {};
        let _res: Result = proto.try_into().expect("Failed conversion");
    }

    #[test]
    fn hash_compare_resp_to_proto() {
        let res = Result {};
        let _proto: ResultProto = res.try_into().expect("Failed conversion");
    }

    #[test]
    fn op_hash_compare_e2e() {
        let op = Operation {
            input: Zeroizing::new(vec![0x11, 0x22, 0x33]),
            hash: Zeroizing::new(vec![0x44, 0x55, 0x66]),
            alg: Hash::Sha256,
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::PsaHashCompare(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(body, Opcode::PsaHashCompare)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::PsaHashCompare)
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
