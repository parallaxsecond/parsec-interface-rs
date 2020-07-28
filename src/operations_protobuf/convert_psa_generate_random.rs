// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::psa_generate_random::{
    Operation as OperationProto, Result as ResultProto,
};
use crate::operations::psa_generate_random::{Operation, Result};
use crate::requests::ResponseStatus;
use std::convert::{TryFrom, TryInto};

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        Ok(Operation {
            size: proto_op.size as usize,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        let mut proto: OperationProto = Default::default();
        proto.size = op.size.try_into()?;
        Ok(proto)
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_result: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {
            random_bytes: proto_result.random_bytes.into(),
        })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(ResultProto {
            random_bytes: result.random_bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::psa_generate_random::Result as ResultProto;
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::psa_generate_random::{Operation, Result};
    use crate::operations::{NativeOperation, NativeResult};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultProto = Default::default();
        proto.random_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let resp: Result = proto.try_into().unwrap();

        assert!(resp.random_bytes[0] == 0xDE);
        assert!(resp.random_bytes[1] == 0xAD);
        assert!(resp.random_bytes[2] == 0xBE);
        assert!(resp.random_bytes[3] == 0xEF);
    }

    #[test]
    fn resp_to_proto() {
        let resp: Result = Result {
            random_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
        };

        let proto: ResultProto = resp.try_into().unwrap();
        assert!(proto.random_bytes[0] == 0xDE);
        assert!(proto.random_bytes[1] == 0xAD);
        assert!(proto.random_bytes[2] == 0xBE);
        assert!(proto.random_bytes[3] == 0xEF);
    }

    #[test]
    fn generate_random_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::PsaGenerateRandom)
            .is_ok());
    }

    #[test]
    fn op_generate_random_from_native() {
        let generate_random = Operation { size: 4 };
        let body = CONVERTER
            .operation_to_body(NativeOperation::PsaGenerateRandom(generate_random))
            .expect("Failed to convert request");
        assert!(!body.is_empty());
    }

    #[test]
    fn op_generate_random_e2e() {
        let generate_random = Operation { size: 4 };
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::PsaGenerateRandom(generate_random))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::PsaGenerateRandom)
            .is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body = RequestBody::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::PsaGenerateRandom)
            .is_err());
    }

    #[test]
    fn generate_random_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::PsaGenerateRandom)
            .is_ok());
    }

    #[test]
    fn result_generate_random_from_native() {
        let generate_random = Result {
            random_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
        };

        let body = CONVERTER
            .result_to_body(NativeResult::PsaGenerateRandom(generate_random))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn generate_random_result_e2e() {
        let generate_random = Result {
            random_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
        };

        let body = CONVERTER
            .result_to_body(NativeResult::PsaGenerateRandom(generate_random))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::PsaGenerateRandom)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::PsaGenerateRandom(result) => {
                assert_eq!(result.random_bytes[0], 0xDE);
                assert_eq!(result.random_bytes[1], 0xAD);
                assert_eq!(result.random_bytes[2], 0xBE);
                assert_eq!(result.random_bytes[3], 0xEF);
            }
            _ => panic!("Expected generate random"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body = ResponseBody::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::PsaGenerateRandom)
            .is_err());
    }
}
