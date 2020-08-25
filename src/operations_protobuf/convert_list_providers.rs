// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::list_providers::{
    Operation as OperationProto, ProviderInfo as ProviderInfoProto, Result as ResultProto,
};
use crate::operations::list_providers::{Operation, ProviderInfo, Result};
use crate::requests::{ProviderID, ResponseStatus};
use std::convert::{TryFrom, TryInto};
use uuid::Uuid;

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

impl TryFrom<ProviderInfoProto> for ProviderInfo {
    type Error = ResponseStatus;

    fn try_from(proto_info: ProviderInfoProto) -> std::result::Result<Self, Self::Error> {
        // UUIDs are strings of 36 ASCII characters (bytes) containing 32 lowercase hexadecimal
        // digits and 4 hyphens.
        let provider_uuid = match Uuid::parse_str(&proto_info.uuid) {
            Ok(provider_uuid) => provider_uuid,
            Err(_) => return Err(ResponseStatus::WrongProviderUuid),
        };
        let id: ProviderID = match u8::try_from(proto_info.id) {
            Ok(id) => id.into(),
            Err(_) => return Err(ResponseStatus::InvalidEncoding),
        };

        Ok(ProviderInfo {
            uuid: provider_uuid,
            description: proto_info.description,
            vendor: proto_info.vendor,
            version_maj: proto_info.version_maj,
            version_min: proto_info.version_min,
            version_rev: proto_info.version_rev,
            id,
        })
    }
}

impl TryFrom<ProviderInfo> for ProviderInfoProto {
    type Error = ResponseStatus;

    fn try_from(info: ProviderInfo) -> std::result::Result<Self, Self::Error> {
        Ok(ProviderInfoProto {
            uuid: info.uuid.to_string(),
            description: info.description,
            vendor: info.vendor,
            version_maj: info.version_maj,
            version_min: info.version_min,
            version_rev: info.version_rev,
            id: info.id.id() as u32,
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultProto) -> std::result::Result<Self, Self::Error> {
        let mut providers: Vec<ProviderInfo> = Vec::new();
        for provider in proto_op.providers {
            providers.push(provider.try_into()?);
        }

        Ok(Result { providers })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(op: Result) -> std::result::Result<Self, Self::Error> {
        let mut providers: Vec<ProviderInfoProto> = Vec::new();
        for provider in op.providers {
            providers.push(provider.try_into()?);
        }

        Ok(ResultProto { providers })
    }
}

#[cfg(test)]
mod test {
    // Operation <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::list_providers::{
        ProviderInfo as ProviderInfoProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::list_providers::{Operation, ProviderInfo, Result};
    use crate::operations::{NativeOperation, NativeResult};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode, ProviderID};
    use std::convert::TryInto;
    use uuid::Uuid;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultProto = Default::default();
        let mut provider_info = ProviderInfoProto::default();
        provider_info.uuid = String::from("9840cd61-9367-4010-bc24-f5b98a6174d1");
        provider_info.description = String::from("provider description");
        provider_info.vendor = String::from("Arm");
        provider_info.version_maj = 0;
        provider_info.version_min = 1;
        provider_info.version_rev = 0;
        provider_info.id = 1;
        proto.providers.push(provider_info);
        let resp: Result = proto.try_into().unwrap();

        assert_eq!(resp.providers.len(), 1);
        assert_eq!(
            resp.providers[0].uuid,
            Uuid::parse_str("9840CD6193674010BC24F5B98A6174D1").unwrap()
        );
        assert_eq!(resp.providers[0].description, "provider description");
        assert_eq!(resp.providers[0].vendor, "Arm");
        assert_eq!(resp.providers[0].version_maj, 0);
        assert_eq!(resp.providers[0].version_min, 1);
        assert_eq!(resp.providers[0].version_rev, 0);
        assert_eq!(resp.providers[0].id, ProviderID::new(1));
    }

    #[test]
    fn resp_to_proto() {
        let mut resp: Result = Result {
            providers: Vec::new(),
        };
        let provider_info = ProviderInfo {
            uuid: Uuid::parse_str("9840CD6193674010BC24F5B98A6174D1").unwrap(),
            description: String::from("provider description"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::new(1),
        };
        resp.providers.push(provider_info);

        let proto: ResultProto = resp.try_into().unwrap();
        assert_eq!(proto.providers.len(), 1);
        assert_eq!(
            proto.providers[0].uuid,
            "9840cd61-9367-4010-bc24-f5b98a6174d1"
        );
        assert_eq!(proto.providers[0].description, "provider description");
        assert_eq!(proto.providers[0].vendor, "Arm");
        assert_eq!(proto.providers[0].version_maj, 0);
        assert_eq!(proto.providers[0].version_min, 1);
        assert_eq!(proto.providers[0].version_rev, 0);
        assert_eq!(proto.providers[0].id, 1);
    }

    #[test]
    fn list_providers_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListProviders)
            .is_ok());
    }

    #[test]
    fn op_list_providers_from_native() {
        let list_providers = Operation {};
        let body = CONVERTER
            .operation_to_body(NativeOperation::ListProviders(list_providers))
            .expect("Failed to convert request");
        assert!(body.is_empty());
    }

    #[test]
    fn op_list_providers_e2e() {
        let list_providers = Operation {};
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::ListProviders(list_providers))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListProviders)
            .is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListProviders)
            .is_err());
    }

    #[test]
    fn list_providers_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListProviders)
            .is_ok());
    }

    #[test]
    fn result_list_providers_from_native() {
        let mut list_providers = Result {
            providers: Vec::new(),
        };
        let provider_info = ProviderInfo {
            uuid: Uuid::parse_str("9840cd61-9367-4010-bc24-f5b98a6174d1").unwrap(),
            description: String::from("provider description"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::new(99),
        };
        list_providers.providers.push(provider_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListProviders(list_providers))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn list_providers_result_e2e() {
        let mut list_providers = Result {
            providers: Vec::new(),
        };
        let provider_info = ProviderInfo {
            uuid: Uuid::parse_str("9840cd61-9367-4010-bc24-f5b98a6174d1").unwrap(),
            description: String::from("provider description"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::new(123),
        };
        list_providers.providers.push(provider_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListProviders(list_providers))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::ListProviders)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::ListProviders(result) => {
                assert_eq!(result.providers.len(), 1);
            }
            _ => panic!("Expected list_providers"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListProviders)
            .is_err());
    }
}
