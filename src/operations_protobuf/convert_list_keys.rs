// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::list_keys::{
    KeyInfo as KeyInfoProto, Operation as OperationProto, Result as ResultProto,
};
use crate::operations::list_keys::{KeyInfo, Operation, Result};
use crate::requests::{ProviderId, ResponseStatus};
use log::error;
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

impl TryFrom<KeyInfoProto> for KeyInfo {
    type Error = ResponseStatus;

    fn try_from(proto_info: KeyInfoProto) -> std::result::Result<Self, Self::Error> {
        let id: ProviderId = match FromPrimitive::from_u32(proto_info.provider_id) {
            Some(id) => id,
            None => return Err(ResponseStatus::ProviderDoesNotExist),
        };

        let attributes = proto_info
            .attributes
            .ok_or_else(|| {
                error!("attributes field of KeyInfo protobuf message is empty.");
                ResponseStatus::InvalidEncoding
            })?
            .try_into()?;

        Ok(KeyInfo {
            provider_id: id,
            name: proto_info.name,
            attributes,
        })
    }
}

impl TryFrom<KeyInfo> for KeyInfoProto {
    type Error = ResponseStatus;

    fn try_from(info: KeyInfo) -> std::result::Result<Self, Self::Error> {
        Ok(KeyInfoProto {
            provider_id: info.provider_id as u32,
            name: info.name,
            attributes: Some(info.attributes.try_into()?),
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultProto) -> std::result::Result<Self, Self::Error> {
        let mut keys: Vec<KeyInfo> = Vec::new();
        for key in proto_op.keys {
            keys.push(key.try_into()?);
        }

        Ok(Result { keys })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(op: Result) -> std::result::Result<Self, Self::Error> {
        let mut keys: Vec<KeyInfoProto> = Vec::new();
        for key in op.keys {
            keys.push(key.try_into()?);
        }

        Ok(ResultProto { keys })
    }
}

#[cfg(test)]
mod test {
    // Operation <-> Proto conversions are not tested since they're too simple
    use super::super::generated_ops::list_keys::{KeyInfo as KeyInfoProto, Result as ResultProto};
    use super::super::generated_ops::psa_key_attributes::KeyAttributes as KeyAttributesProto;
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::list_keys::{KeyInfo, Operation, Result};
    use crate::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
    use crate::operations::psa_key_attributes::{self, Attributes, Lifetime, Policy, UsageFlags};
    use crate::operations::{NativeOperation, NativeResult};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode, ProviderId};
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultProto = Default::default();

        let key_attrs = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: psa_key_attributes::Type::RsaKeyPair,
            bits: 1024,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: true,
                    copy: true,
                    cache: true,
                    encrypt: true,
                    decrypt: true,
                    sign_message: true,
                    verify_message: true,
                    sign_hash: true,
                    verify_hash: true,
                    derive: true,
                },
                permitted_algorithms: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: Hash::Sha1.into(),
                    },
                ),
            },
        };

        let key_attrs_proto: KeyAttributesProto = key_attrs.try_into().unwrap();
        let key_info = KeyInfoProto {
            provider_id: ProviderId::MbedCrypto as u32,
            name: String::from("Some Key Name"),
            attributes: Some(key_attrs_proto),
        };
        proto.keys.push(key_info);

        let resp: Result = proto.try_into().unwrap();

        assert_eq!(resp.keys.len(), 1);
        assert_eq!(resp.keys[0].name, "Some Key Name");
        assert_eq!(resp.keys[0].provider_id, ProviderId::MbedCrypto);
        assert_eq!(resp.keys[0].attributes, key_attrs);
    }

    #[test]
    fn resp_to_proto() {
        let mut resp: Result = Result { keys: Vec::new() };
        let key_attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: psa_key_attributes::Type::RsaKeyPair,
            bits: 1024,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: true,
                    copy: true,
                    cache: true,
                    encrypt: true,
                    decrypt: true,
                    sign_message: true,
                    verify_message: true,
                    sign_hash: true,
                    verify_hash: true,
                    derive: true,
                },
                permitted_algorithms: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: Hash::Sha1.into(),
                    },
                ),
            },
        };
        let key_info = KeyInfo {
            provider_id: ProviderId::MbedCrypto,
            name: String::from("Foo"),
            attributes: key_attributes,
        };
        resp.keys.push(key_info);

        let proto: ResultProto = resp.try_into().unwrap();
        let key_attributes_proto: KeyAttributesProto = key_attributes.try_into().unwrap();

        assert_eq!(proto.keys.len(), 1);
        assert_eq!(proto.keys[0].provider_id, ProviderId::MbedCrypto as u32);
        assert_eq!(proto.keys[0].name, "Foo");
        assert_eq!(proto.keys[0].attributes, Some(key_attributes_proto));
    }

    #[test]
    fn list_keys_req_to_native() {
        let req_body = RequestBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListKeys)
            .is_ok());
    }

    #[test]
    fn op_list_keys_from_native() {
        let list_keys = Operation {};
        let body = CONVERTER
            .operation_to_body(NativeOperation::ListKeys(list_keys))
            .expect("Failed to convert request");
        assert!(body.is_empty());
    }

    #[test]
    fn op_list_keys_e2e() {
        let list_keys = Operation {};
        let req_body = CONVERTER
            .operation_to_body(NativeOperation::ListKeys(list_keys))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListKeys)
            .is_ok());
    }

    #[test]
    fn req_from_native_mangled_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::ListKeys)
            .is_err());
    }

    #[test]
    fn list_keys_body_to_native() {
        let resp_body = ResponseBody::from_bytes(Vec::new());
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListKeys)
            .is_ok());
    }

    #[test]
    fn result_list_keys_from_native() {
        let mut list_keys = Result { keys: Vec::new() };
        let key_info = KeyInfo {
            provider_id: ProviderId::MbedCrypto,
            name: String::from("Bar"),
            attributes: Attributes {
                lifetime: Lifetime::Persistent,
                key_type: psa_key_attributes::Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags: UsageFlags {
                        export: true,
                        copy: true,
                        cache: true,
                        encrypt: true,
                        decrypt: true,
                        sign_message: true,
                        verify_message: true,
                        sign_hash: true,
                        verify_hash: true,
                        derive: true,
                    },
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Sha1.into(),
                        },
                    ),
                },
            },
        };
        list_keys.keys.push(key_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListKeys(list_keys))
            .expect("Failed to convert response");
        assert!(!body.is_empty());
    }

    #[test]
    fn list_keys_result_e2e() {
        let mut list_keys = Result { keys: Vec::new() };
        let key_info = KeyInfo {
            provider_id: ProviderId::MbedCrypto,
            name: String::from("Baz"),
            attributes: Attributes {
                lifetime: Lifetime::Persistent,
                key_type: psa_key_attributes::Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags: UsageFlags {
                        export: true,
                        copy: true,
                        cache: true,
                        encrypt: true,
                        decrypt: true,
                        sign_message: true,
                        verify_message: true,
                        sign_hash: true,
                        verify_hash: true,
                        derive: true,
                    },
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Sha1.into(),
                        },
                    ),
                },
            },
        };
        list_keys.keys.push(key_info);

        let body = CONVERTER
            .result_to_body(NativeResult::ListKeys(list_keys))
            .expect("Failed to convert response");
        assert!(!body.is_empty());

        let result = CONVERTER
            .body_to_result(body, Opcode::ListKeys)
            .expect("Failed to convert back to result");

        match result {
            NativeResult::ListKeys(result) => {
                assert_eq!(result.keys.len(), 1);
            }
            _ => panic!("Expected list_keys"),
        }
    }

    #[test]
    fn resp_from_native_mangled_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::ListKeys)
            .is_err());
    }
}
