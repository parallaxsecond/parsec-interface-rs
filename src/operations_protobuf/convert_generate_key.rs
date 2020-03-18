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
use super::generated_ops::generate_key::{Operation as OperationProto, Result as ResultProto};
use crate::operations::generate_key::{Operation, Result};
use crate::requests::ResponseStatus;
use log::error;
use std::convert::{TryFrom, TryInto};

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        Ok(Operation {
            key_name: proto_op.key_name,
            attributes: proto_op
                .attributes
                .ok_or_else(|| {
                    error!("attributes field of GenerateKey::Operation message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        let mut proto: OperationProto = Default::default();
        proto.key_name = op.key_name;
        proto.attributes = Some(op.attributes.try_into()?);

        Ok(proto)
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(_result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(_response: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {})
    }
}

#[cfg(test)]
mod test {
    #![allow(deprecated)]

    use super::super::generated_ops::algorithm::{
        self as algorithm_proto, Algorithm as AlgorithmProto,
    };
    use super::super::generated_ops::generate_key::{
        Operation as OperationProto, Result as ResultProto,
    };
    use super::super::generated_ops::key_attributes::{
        self as key_attributes_proto, KeyAttributes as KeyAttributesProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::algorithm::{Algorithm, AsymmetricSignature, Hash};
    use crate::operations::generate_key::{Operation, Result};
    use crate::operations::key_attributes::{self, KeyAttributes, KeyPolicy, UsageFlags};
    use crate::operations::NativeOperation;
    use crate::requests::Opcode;
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn create_key_op_from_proto() {
        let name = "test name".to_string();
        let proto = OperationProto {
            key_name: name.clone(),
            attributes: Some(get_key_attrs_proto()),
        };

        let op: Operation = proto.try_into().expect("Failed conversion");
        assert_eq!(op.key_name, name);
    }

    #[test]
    fn create_key_op_to_proto() {
        let name = "test name".to_string();
        let op = Operation {
            key_name: name.clone(),
            attributes: get_key_attrs(),
        };

        let proto: OperationProto = op.try_into().expect("Failed conversion");
        assert_eq!(proto.key_name, name);
    }

    #[test]
    fn create_key_res_from_proto() {
        let proto = ResultProto {};
        let _res: Result = proto.try_into().expect("Failed conversion");
    }

    #[test]
    fn create_key_res_to_proto() {
        let res = Result {};
        let _proto: ResultProto = res.try_into().expect("Failed conversion");
    }

    #[test]
    fn create_key_op_e2e() {
        let name = "test name".to_string();
        let op = Operation {
            key_name: name,
            attributes: get_key_attrs(),
        };

        let body = CONVERTER
            .operation_to_body(NativeOperation::GenerateKey(op))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_operation(body, Opcode::GenerateKey)
            .expect("Failed to convert to operation");
    }

    fn get_key_attrs() -> KeyAttributes {
        KeyAttributes {
            key_type: key_attributes::KeyType::RsaKeyPair,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
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
                key_algorithm: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: Hash::Sha1,
                    },
                ),
            },
        }
    }

    fn get_key_attrs_proto() -> KeyAttributesProto {
        KeyAttributesProto {
            key_type: Some(key_attributes_proto::KeyType {
                variant: Some(key_attributes_proto::key_type::Variant::RsaKeyPair(key_attributes_proto::key_type::RsaKeyPair {})),
            }),
            key_bits: 1024,
            key_policy: Some(key_attributes_proto::KeyPolicy {
                key_usage_flags: Some(key_attributes_proto::UsageFlags {
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
                }),
                key_algorithm: Some(AlgorithmProto {
                    variant: Some(algorithm_proto::algorithm::Variant::AsymmetricSignature(algorithm_proto::algorithm::AsymmetricSignature {
                        variant: Some(algorithm_proto::algorithm::asymmetric_signature::Variant::RsaPkcs1v15Sign(algorithm_proto::algorithm::asymmetric_signature::RsaPkcs1v15Sign {
                            hash_alg: algorithm_proto::algorithm::Hash::Sha1.into(),
                        })),
                    }))
                }),
            }),
        }
    }
}
