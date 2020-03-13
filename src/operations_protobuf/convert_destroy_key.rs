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
use super::generated_ops::destroy_key::{Operation as OperationProto, Result as ResultProto};
use crate::operations::destroy_key::{Operation, Result};
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
    use super::super::generated_ops::destroy_key::{
        Operation as OperationProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{destroy_key::Operation, destroy_key::Result, NativeOperation};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn destroy_key_proto_to_op() {
        let mut proto: OperationProto = Default::default();
        let key_name = "test name".to_string();
        proto.key_name = key_name.clone();

        let op: Operation = proto.try_into().expect("Failed to convert");

        assert_eq!(op.key_name, key_name);
    }

    #[test]
    fn destroy_key_op_to_proto() {
        let key_name = "test name".to_string();
        let op = Operation {
            key_name: key_name.clone(),
        };

        let proto: OperationProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.key_name, key_name);
    }

    #[test]
    fn destroy_key_proto_to_resp() {
        let proto: ResultProto = Default::default();

        let _result: Result = proto.try_into().expect("Failed to convert");
    }

    #[test]
    fn destroy_key_resp_to_proto() {
        let result = Result {};

        let _proto: ResultProto = result.try_into().expect("Failed to convert");
    }

    #[test]
    fn op_destroy_key_e2e() {
        let op = Operation {
            key_name: "test name".to_string(),
        };
        let body = CONVERTER
            .operation_to_body(NativeOperation::DestroyKey(op))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(body, Opcode::DestroyKey)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::DestroyKey)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::DestroyKey)
            .is_err());
    }
}
