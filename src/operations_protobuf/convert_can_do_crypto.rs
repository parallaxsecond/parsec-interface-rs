// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::can_do_crypto::{
    CheckType as CheckTypeProto, Operation as OperationProto, Result as ResultProto,
};
use crate::operations::can_do_crypto::{CheckType, Operation, Result};
use crate::requests::ResponseStatus;
use log::error;
use std::convert::{TryFrom, TryInto};

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        let key_attributes = proto_op.attributes.ok_or_else(|| {
            error!("The attributes field of CanDoCrypto::Operation message is not set (mandatory field).");
            ResponseStatus::InvalidEncoding
        })?;
        Ok(Operation {
            check_type: i32_to_check_type(proto_op.check_type)?,
            attributes: key_attributes.try_into()?,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(OperationProto {
            check_type: check_type_to_i32(op.check_type),
            attributes: Some(op.attributes.try_into()?),
        })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(_result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(ResultProto {})
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(_response: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {})
    }
}

// CheckType: from protobuf to native
impl TryFrom<CheckTypeProto> for CheckType {
    type Error = ResponseStatus;

    fn try_from(check_type_proto_val: CheckTypeProto) -> std::result::Result<Self, Self::Error> {
        match check_type_proto_val {
            CheckTypeProto::ChecktypeNone => Err(ResponseStatus::InvalidEncoding),
            CheckTypeProto::Use => Ok(CheckType::Use),
            CheckTypeProto::Generate => Ok(CheckType::Generate),
            CheckTypeProto::Import => Ok(CheckType::Import),
            CheckTypeProto::Derive => Ok(CheckType::Derive),
        }
    }
}

// CheckType: from native to protobuf
impl TryFrom<CheckType> for CheckTypeProto {
    type Error = ResponseStatus;

    fn try_from(check_type_val: CheckType) -> std::result::Result<Self, Self::Error> {
        match check_type_val {
            CheckType::Use => Ok(CheckTypeProto::Use),
            CheckType::Generate => Ok(CheckTypeProto::Generate),
            CheckType::Import => Ok(CheckTypeProto::Import),
            CheckType::Derive => Ok(CheckTypeProto::Derive),
        }
    }
}

// CheckType from protobuf to native
pub fn i32_to_check_type(check_type_val: i32) -> std::result::Result<CheckType, ResponseStatus> {
    let check_type_proto: CheckTypeProto = check_type_val.try_into()?;
    check_type_proto.try_into()
}

// CheckType from native to protobuf
pub fn check_type_to_i32(check_type: CheckType) -> i32 {
    match check_type {
        CheckType::Use => CheckTypeProto::Use.into(),
        CheckType::Generate => CheckTypeProto::Generate.into(),
        CheckType::Import => CheckTypeProto::Import.into(),
        CheckType::Derive => CheckTypeProto::Derive.into(),
    }
}

#[cfg(test)]
mod test {

    use super::super::generated_ops::can_do_crypto::Operation as OperationProto;
    use crate::operations::can_do_crypto::{CheckType, Operation};
    use crate::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
    use crate::operations::psa_key_attributes::{self, Attributes, Lifetime, Policy, UsageFlags};
    use crate::operations_protobuf::convert_can_do_crypto::check_type_to_i32;
    use std::convert::TryInto;

    #[test]
    fn proto_to_resp() {
        let mut usage_flags: UsageFlags = Default::default();
        let _ = usage_flags
            .set_export()
            .set_copy()
            .set_cache()
            .set_encrypt()
            .set_decrypt()
            .set_sign_message()
            .set_verify_message()
            .set_sign_hash()
            .set_verify_hash()
            .set_derive();
        let key_attrs = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: psa_key_attributes::Type::RsaKeyPair,
            bits: 1024,
            policy: Policy {
                usage_flags,
                permitted_algorithms: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: Hash::Sha1.into(),
                    },
                ),
            },
        };
        let proto = OperationProto {
            check_type: check_type_to_i32(CheckType::Use),
            attributes: Some(key_attrs.try_into().expect("Failed conversion")),
        };

        let resp: Operation = proto.try_into().expect("Failed conversion");

        assert_eq!(resp.check_type, CheckType::Use);
        assert_eq!(resp.attributes, key_attrs);
    }

    #[test]
    fn resp_to_proto() {
        let mut usage_flags: UsageFlags = Default::default();
        let _ = usage_flags
            .set_export()
            .set_copy()
            .set_cache()
            .set_encrypt()
            .set_decrypt()
            .set_sign_message()
            .set_verify_message()
            .set_sign_hash()
            .set_verify_hash()
            .set_derive();
        let key_attrs = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: psa_key_attributes::Type::RsaKeyPair,
            bits: 1024,
            policy: Policy {
                usage_flags,
                permitted_algorithms: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: Hash::Sha1.into(),
                    },
                ),
            },
        };
        let resp: Operation = Operation {
            check_type: CheckType::Use,
            attributes: key_attrs,
        };

        let proto: OperationProto = resp.try_into().expect("Failed conversion");

        assert_eq!(proto.check_type, check_type_to_i32(CheckType::Use));
        assert_eq!(
            proto.attributes.expect("Failed conversion"),
            key_attrs.try_into().expect("Failed conversion")
        );
    }
}
