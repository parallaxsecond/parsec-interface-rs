// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::ping::{Operation as OperationProto, Result as ResultProto};
use crate::operations::ping::{Operation, Result};
use crate::requests::ResponseStatus;
use std::convert::TryFrom;

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(_proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        Ok(Operation {})
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(_proto_op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(result: Result) -> std::result::Result<Self, Self::Error> {
        let mut proto_response: ResultProto = Default::default();
        proto_response.wire_protocol_version_maj = u32::from(result.wire_protocol_version_maj);
        proto_response.wire_protocol_version_min = u32::from(result.wire_protocol_version_min);

        Ok(proto_response)
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(response: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {
            wire_protocol_version_maj: u8::try_from(response.wire_protocol_version_maj)?,
            wire_protocol_version_min: u8::try_from(response.wire_protocol_version_min)?,
        })
    }
}

#[cfg(test)]
mod test {
    // Operation <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::ping::Result as ResultProto;
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::ping::{Operation, Result};
    use crate::operations::{NativeOperation, NativeResult};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultProto = Default::default();
        proto.wire_protocol_version_maj = 1;
        proto.wire_protocol_version_min = 1;
        let resp: Result = proto.try_into().unwrap();

        assert!(resp.wire_protocol_version_maj == 1);
        assert!(resp.wire_protocol_version_min == 1);
    }

    #[test]
    fn resp_to_proto() {
        let resp: Result = Result {
            wire_protocol_version_maj: 1,
            wire_protocol_version_min: 1,
        };

        let proto: ResultProto = resp.try_into().unwrap();
        assert!(proto.wire_protocol_version_maj == 1);
        assert!(proto.wire_protocol_version_min == 1);
    }

    #[test]
    fn ping_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER.body_to_operation(req_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn op_ping_from_native() {
        let ping = Operation {};
        let body = CONVERTER
            .operation_to_body(NativeOperation::Ping(ping))
            .expect("Failed to convert request");
        assert!(body.is_empty());
    }

    #[test]
    fn op_ping_e2e() {
        let ping = Operation {};
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::Ping(ping))
            .expect("Failed to convert request");

        assert!(CONVERTER.body_to_operation(req_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER.body_to_operation(req_body, Opcode::Ping).is_err());
    }

    #[test]
    fn ping_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER.body_to_result(resp_body, Opcode::Ping).is_ok());
    }

    #[test]
    fn result_ping_from_native() {
        let ping = Result {
            wire_protocol_version_maj: 1,
            wire_protocol_version_min: 0,
        };

        let body = CONVERTER
            .result_to_body(NativeResult::Ping(ping))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn ping_result_e2e() {
        let ping = Result {
            wire_protocol_version_maj: 1,
            wire_protocol_version_min: 0,
        };

        let body = CONVERTER
            .result_to_body(NativeResult::Ping(ping))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::Ping)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::Ping(result) => {
                assert_eq!(result.wire_protocol_version_maj, 1);
                assert_eq!(result.wire_protocol_version_min, 0);
            }
            _ => panic!("Expected ping"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER.body_to_result(resp_body, Opcode::Ping).is_err());
    }
}
