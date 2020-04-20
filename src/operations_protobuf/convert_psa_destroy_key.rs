// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::psa_destroy_key::{Operation as OperationProto, Result as ResultProto};
use crate::operations::psa_destroy_key::{Operation, Result};
use crate::requests::ResponseStatus;
use std::convert::TryFrom;

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        Ok(Operation {
            key_name: proto_op.key_name,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(OperationProto {
            key_name: op.key_name,
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(_proto_result: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {})
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
    use super::super::generated_ops::psa_destroy_key::{
        Operation as OperationProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{psa_destroy_key::Operation, psa_destroy_key::Result, NativeOperation};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn psa_destroy_key_proto_to_op() {
        let mut proto: OperationProto = Default::default();
        let key_name = "test name".to_string();
        proto.key_name = key_name.clone();

        let op: Operation = proto.try_into().expect("Failed to convert");

        assert_eq!(op.key_name, key_name);
    }

    #[test]
    fn psa_destroy_key_op_to_proto() {
        let key_name = "test name".to_string();
        let op = Operation {
            key_name: key_name.clone(),
        };

        let proto: OperationProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.key_name, key_name);
    }

    #[test]
    fn psa_destroy_key_proto_to_resp() {
        let proto: ResultProto = Default::default();

        let _result: Result = proto.try_into().expect("Failed to convert");
    }

    #[test]
    fn psa_destroy_key_resp_to_proto() {
        let result = Result {};

        let _proto: ResultProto = result.try_into().expect("Failed to convert");
    }

    #[test]
    fn op_psa_destroy_key_e2e() {
        let op = Operation {
            key_name: "test name".to_string(),
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::PsaDestroyKey(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(body, Opcode::PsaDestroyKey)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::PsaDestroyKey)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::PsaDestroyKey)
            .is_err());
    }
}
