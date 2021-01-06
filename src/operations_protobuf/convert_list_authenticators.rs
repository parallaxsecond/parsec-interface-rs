// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::list_authenticators::{
    AuthenticatorInfo as AuthenticatorInfoProto, Operation as OperationProto, Result as ResultProto,
};
use crate::operations::list_authenticators::{AuthenticatorInfo, Operation, Result};
use crate::requests::{AuthType, ResponseStatus};
use num::FromPrimitive;
use std::convert::{TryFrom, TryInto};

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(_proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        Ok(Operation {})
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(_op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<AuthenticatorInfoProto> for AuthenticatorInfo {
    type Error = ResponseStatus;

    fn try_from(proto_info: AuthenticatorInfoProto) -> std::result::Result<Self, Self::Error> {
        let id: AuthType = match FromPrimitive::from_u32(proto_info.id) {
            Some(id) => id,
            None => return Err(ResponseStatus::AuthenticatorDoesNotExist),
        };

        Ok(AuthenticatorInfo {
            description: proto_info.description,
            version_maj: proto_info.version_maj,
            version_min: proto_info.version_min,
            version_rev: proto_info.version_rev,
            id,
        })
    }
}

impl TryFrom<AuthenticatorInfo> for AuthenticatorInfoProto {
    type Error = ResponseStatus;

    fn try_from(info: AuthenticatorInfo) -> std::result::Result<Self, Self::Error> {
        Ok(AuthenticatorInfoProto {
            description: info.description,
            version_maj: info.version_maj,
            version_min: info.version_min,
            version_rev: info.version_rev,
            id: info.id as u32,
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultProto) -> std::result::Result<Self, Self::Error> {
        let mut authenticators: Vec<AuthenticatorInfo> = Vec::new();
        for authenticator in proto_op.authenticators {
            authenticators.push(authenticator.try_into()?);
        }

        Ok(Result { authenticators })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(op: Result) -> std::result::Result<Self, Self::Error> {
        let mut authenticators: Vec<AuthenticatorInfoProto> = Vec::new();
        for authenticator in op.authenticators {
            authenticators.push(authenticator.try_into()?);
        }

        Ok(ResultProto { authenticators })
    }
}

#[cfg(test)]
mod test {
    // Operation <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::list_authenticators::{
        AuthenticatorInfo as AuthenticatorInfoProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::list_authenticators::{AuthenticatorInfo, Operation, Result};
    use crate::operations::{NativeOperation, NativeResult};
    use crate::requests::{request::RequestBody, response::ResponseBody, AuthType, Opcode};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultProto = Default::default();
        let authenticator_info = AuthenticatorInfoProto {
            description: String::from("authenticator description"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: AuthType::Direct as u32,
        };
        proto.authenticators.push(authenticator_info);
        let resp: Result = proto.try_into().unwrap();

        assert_eq!(resp.authenticators.len(), 1);
        assert_eq!(
            resp.authenticators[0].description,
            "authenticator description"
        );
        assert_eq!(resp.authenticators[0].version_maj, 0);
        assert_eq!(resp.authenticators[0].version_min, 1);
        assert_eq!(resp.authenticators[0].version_rev, 0);
        assert_eq!(resp.authenticators[0].id, AuthType::Direct);
    }

    #[test]
    fn resp_to_proto() {
        let mut resp: Result = Result {
            authenticators: Vec::new(),
        };
        let authenticator_info = AuthenticatorInfo {
            description: String::from("authenticator description"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: AuthType::Direct,
        };
        resp.authenticators.push(authenticator_info);

        let proto: ResultProto = resp.try_into().unwrap();
        assert_eq!(proto.authenticators.len(), 1);
        assert_eq!(
            proto.authenticators[0].description,
            "authenticator description"
        );
        assert_eq!(proto.authenticators[0].version_maj, 0);
        assert_eq!(proto.authenticators[0].version_min, 1);
        assert_eq!(proto.authenticators[0].version_rev, 0);
        assert_eq!(proto.authenticators[0].id, AuthType::Direct as u32);
    }

    #[test]
    fn list_authenticators_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListAuthenticators)
            .is_ok());
    }

    #[test]
    fn op_list_authenticators_from_native() {
        let list_authenticators = Operation {};
        let body = CONVERTER
            .operation_to_body(NativeOperation::ListAuthenticators(list_authenticators))
            .expect("Failed to convert request");
        assert!(body.is_empty());
    }

    #[test]
    fn op_list_authenticators_e2e() {
        let list_authenticators = Operation {};
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::ListAuthenticators(list_authenticators))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListAuthenticators)
            .is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListAuthenticators)
            .is_err());
    }

    #[test]
    fn list_authenticators_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListAuthenticators)
            .is_ok());
    }

    #[test]
    fn result_list_authenticators_from_native() {
        let mut list_authenticators = Result {
            authenticators: Vec::new(),
        };
        let authenticator_info = AuthenticatorInfo {
            description: String::from("authenticator description"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: AuthType::Direct,
        };
        list_authenticators.authenticators.push(authenticator_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListAuthenticators(list_authenticators))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn list_authenticators_result_e2e() {
        let mut list_authenticators = Result {
            authenticators: Vec::new(),
        };
        let authenticator_info = AuthenticatorInfo {
            description: String::from("authenticator description"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: AuthType::Direct,
        };
        list_authenticators.authenticators.push(authenticator_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListAuthenticators(list_authenticators))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::ListAuthenticators)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::ListAuthenticators(result) => {
                assert_eq!(result.authenticators.len(), 1);
            }
            _ => panic!("Expected list_authenticators"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListAuthenticators)
            .is_err());
    }
}
