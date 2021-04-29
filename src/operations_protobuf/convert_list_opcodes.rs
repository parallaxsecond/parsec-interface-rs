// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::list_opcodes::{Operation as OperationProto, Result as ResultProto};
use crate::operations::list_opcodes::{Operation, Result};
use crate::requests::{Opcode, ResponseStatus};
use log::error;
use num::FromPrimitive;
use std::collections::HashSet;
use std::convert::TryFrom;

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        match FromPrimitive::from_u32(proto_op.provider_id) {
            None => {
                error!("Invalid provider ID: {}", proto_op.provider_id);
                Err(ResponseStatus::ProviderDoesNotExist)
            }
            Some(provider_id) => Ok(Operation { provider_id }),
        }
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(OperationProto {
            provider_id: op.provider_id as u32,
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultProto) -> std::result::Result<Self, Self::Error> {
        let mut opcodes: HashSet<Opcode> = HashSet::new();
        for opcode in proto_op.opcodes {
            let opcode = match FromPrimitive::from_u32(opcode) {
                Some(code) => code,
                None => return Err(ResponseStatus::OpcodeDoesNotExist),
            };
            let _ = opcodes.insert(opcode);
        }

        Ok(Result { opcodes })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(op: Result) -> std::result::Result<Self, Self::Error> {
        let mut opcodes: Vec<u32> = Vec::new();
        for opcode in op.opcodes {
            opcodes.push(opcode as u32);
        }

        Ok(ResultProto { opcodes })
    }
}

#[cfg(test)]
mod test {
    // Operation <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::list_opcodes::Result as ResultProto;
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{
        list_opcodes::Operation, list_opcodes::Result, NativeOperation, NativeResult,
    };
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode, ProviderId};
    use std::collections::HashSet;
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultProto = Default::default();
        proto.opcodes.push(1);
        let resp: Result = proto.try_into().unwrap();

        assert_eq!(resp.opcodes.len(), 1);
        assert!(resp.opcodes.contains(&Opcode::Ping));
    }

    #[test]
    fn resp_to_proto() {
        let mut resp: Result = Result {
            opcodes: HashSet::new(),
        };
        let _ = resp.opcodes.insert(Opcode::Ping);

        let proto: ResultProto = resp.try_into().unwrap();
        assert_eq!(proto.opcodes.len(), 1);
        assert_eq!(proto.opcodes[0], 1);
    }

    #[test]
    fn list_opcodes_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListOpcodes)
            .is_ok());
    }

    #[test]
    fn op_list_opcodes_from_native() {
        let list_opcodes = Operation {
            provider_id: ProviderId::Core,
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::ListOpcodes(list_opcodes))
            .expect("Failed to convert request");
        assert!(body.is_empty());
    }

    #[test]
    fn op_list_opcodes_e2e() {
        let list_opcodes = Operation {
            provider_id: ProviderId::Pkcs11,
        };
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::ListOpcodes(list_opcodes))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListOpcodes)
            .is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListOpcodes)
            .is_err());
    }

    #[test]
    fn list_opcodes_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListOpcodes)
            .is_ok());
    }

    #[test]
    fn result_list_opcodes_from_native() {
        let mut list_opcodes = Result {
            opcodes: HashSet::new(),
        };
        let _ = list_opcodes.opcodes.insert(Opcode::Ping);

        let body = CONVERTER
            .result_to_body(NativeResult::ListOpcodes(list_opcodes))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn list_opcodes_result_e2e() {
        let mut list_opcodes = Result {
            opcodes: HashSet::new(),
        };
        let _ = list_opcodes.opcodes.insert(Opcode::Ping);

        let body = CONVERTER
            .result_to_body(NativeResult::ListOpcodes(list_opcodes))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::ListOpcodes)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::ListOpcodes(result) => {
                assert_eq!(result.opcodes.len(), 1);
            }
            _ => panic!("Expected list_opcodes"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListOpcodes)
            .is_err());
    }
}
