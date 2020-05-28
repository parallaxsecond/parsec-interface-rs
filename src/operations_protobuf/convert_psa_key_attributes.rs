// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// Protobuf imports
use super::generated_ops::psa_key_attributes::key_type;
use super::generated_ops::psa_key_attributes::{
    key_type::DhFamily as DhFamilyProto, key_type::EccFamily as EccFamilyProto,
    KeyAttributes as KeyAttributesProto, KeyPolicy as KeyPolicyProto, KeyType as KeyTypeProto,
    UsageFlags as UsageFlagsProto,
};
// Native imports
use crate::operations::psa_algorithm::Algorithm;
use crate::operations::psa_key_attributes::{
    Attributes, DhFamily, EccFamily, Lifetime, Policy, Type, UsageFlags,
};

use crate::requests::{ResponseStatus, Result};
use log::error;
use std::convert::{TryFrom, TryInto};

// UsageFlags: from protobuf to native
impl TryFrom<UsageFlagsProto> for UsageFlags {
    type Error = ResponseStatus;

    fn try_from(usage_flags_proto: UsageFlagsProto) -> Result<Self> {
        Ok(UsageFlags {
            export: usage_flags_proto.export,
            copy: usage_flags_proto.copy,
            cache: usage_flags_proto.cache,
            encrypt: usage_flags_proto.encrypt,
            decrypt: usage_flags_proto.decrypt,
            sign_message: usage_flags_proto.sign_message,
            verify_message: usage_flags_proto.verify_message,
            sign_hash: usage_flags_proto.sign_hash,
            verify_hash: usage_flags_proto.verify_hash,
            derive: usage_flags_proto.derive,
        })
    }
}

// UsageFlags: from native to protobuf
impl TryFrom<UsageFlags> for UsageFlagsProto {
    type Error = ResponseStatus;

    fn try_from(usage_flags: UsageFlags) -> Result<Self> {
        Ok(UsageFlagsProto {
            export: usage_flags.export,
            copy: usage_flags.copy,
            cache: usage_flags.cache,
            encrypt: usage_flags.encrypt,
            decrypt: usage_flags.decrypt,
            sign_message: usage_flags.sign_message,
            verify_message: usage_flags.verify_message,
            sign_hash: usage_flags.sign_hash,
            verify_hash: usage_flags.verify_hash,
            derive: usage_flags.derive,
        })
    }
}

// Policy: from protobuf to native
impl TryFrom<KeyPolicyProto> for Policy {
    type Error = ResponseStatus;

    fn try_from(key_policy_proto: KeyPolicyProto) -> Result<Self> {
        let permitted_algorithms: Algorithm = key_policy_proto
            .key_algorithm
            .ok_or_else(|| {
                error!("permitted_algorithms field of Policy message is empty.");
                ResponseStatus::InvalidEncoding
            })?
            .try_into()?;
        Ok(Policy {
            usage_flags: key_policy_proto
                .key_usage_flags
                .ok_or_else(|| {
                    error!("usage_flags field of Policy message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
            permitted_algorithms,
        })
    }
}

// Policy: from native to protobuf
impl TryFrom<Policy> for KeyPolicyProto {
    type Error = ResponseStatus;

    fn try_from(key_policy: Policy) -> Result<Self> {
        Ok(KeyPolicyProto {
            key_usage_flags: Some(key_policy.usage_flags.try_into()?),
            key_algorithm: Some(key_policy.permitted_algorithms.try_into()?),
        })
    }
}

// EccFamily: from protobuf to native
impl TryFrom<EccFamilyProto> for EccFamily {
    type Error = ResponseStatus;

    fn try_from(ecc_family_val: EccFamilyProto) -> Result<Self> {
        match ecc_family_val {
            EccFamilyProto::None => {
                error!("The None value of EccFamily enumeration is not allowed.");
                Err(ResponseStatus::InvalidEncoding)
            }
            EccFamilyProto::SecpK1 => Ok(EccFamily::SecpK1),
            EccFamilyProto::SecpR1 => Ok(EccFamily::SecpR1),
            #[allow(deprecated)]
            EccFamilyProto::SecpR2 => Ok(EccFamily::SecpR2),
            EccFamilyProto::SectK1 => Ok(EccFamily::SectK1),
            EccFamilyProto::SectR1 => Ok(EccFamily::SectR1),
            #[allow(deprecated)]
            EccFamilyProto::SectR2 => Ok(EccFamily::SectR2),
            EccFamilyProto::BrainpoolPR1 => Ok(EccFamily::BrainpoolPR1),
            EccFamilyProto::Frp => Ok(EccFamily::Frp),
            EccFamilyProto::Montgomery => Ok(EccFamily::Montgomery),
        }
    }
}

// EccFamily: from native to protobuf
fn ecc_family_to_i32(ecc_family: EccFamily) -> i32 {
    match ecc_family {
        EccFamily::SecpK1 => EccFamilyProto::SecpK1.into(),
        EccFamily::SecpR1 => EccFamilyProto::SecpR1.into(),
        #[allow(deprecated)]
        EccFamily::SecpR2 => EccFamilyProto::SecpR2.into(),
        EccFamily::SectK1 => EccFamilyProto::SectK1.into(),
        EccFamily::SectR1 => EccFamilyProto::SectR1.into(),
        #[allow(deprecated)]
        EccFamily::SectR2 => EccFamilyProto::SectR2.into(),
        EccFamily::BrainpoolPR1 => EccFamilyProto::BrainpoolPR1.into(),
        EccFamily::Frp => EccFamilyProto::Frp.into(),
        EccFamily::Montgomery => EccFamilyProto::Montgomery.into(),
    }
}

// DhFamily: from protobuf to native
impl TryFrom<DhFamilyProto> for DhFamily {
    type Error = ResponseStatus;

    fn try_from(dh_family_val: DhFamilyProto) -> Result<Self> {
        match dh_family_val {
            DhFamilyProto::Rfc7919 => Ok(DhFamily::Rfc7919),
        }
    }
}

// DhFamily: from native to protobuf
fn dh_family_to_i32(dh_family: DhFamily) -> i32 {
    match dh_family {
        DhFamily::Rfc7919 => DhFamilyProto::Rfc7919.into(),
    }
}

impl TryFrom<KeyTypeProto> for Type {
    type Error = ResponseStatus;

    fn try_from(key_type_proto: KeyTypeProto) -> Result<Self> {
        match key_type_proto.variant.ok_or_else(|| {
            error!("variant field of Type message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            key_type::Variant::RawData(_) => Ok(Type::RawData),
            key_type::Variant::Hmac(_) => Ok(Type::Hmac),
            key_type::Variant::Derive(_) => Ok(Type::Derive),
            key_type::Variant::Aes(_) => Ok(Type::Aes),
            key_type::Variant::Des(_) => Ok(Type::Des),
            key_type::Variant::Camellia(_) => Ok(Type::Camellia),
            key_type::Variant::Arc4(_) => Ok(Type::Arc4),
            key_type::Variant::Chacha20(_) => Ok(Type::Chacha20),
            key_type::Variant::RsaPublicKey(_) => Ok(Type::RsaPublicKey),
            key_type::Variant::RsaKeyPair(_) => Ok(Type::RsaKeyPair),
            key_type::Variant::EccKeyPair(ecc_key_pair) => Ok(Type::EccKeyPair {
                curve_family: EccFamilyProto::try_from(ecc_key_pair.curve_family)?.try_into()?,
            }),
            key_type::Variant::EccPublicKey(ecc_public_key) => Ok(Type::EccPublicKey {
                curve_family: EccFamilyProto::try_from(ecc_public_key.curve_family)?.try_into()?,
            }),
            key_type::Variant::DhKeyPair(dh_key_pair) => Ok(Type::DhKeyPair {
                group_family: DhFamilyProto::try_from(dh_key_pair.group_family)?.try_into()?,
            }),
            key_type::Variant::DhPublicKey(dh_public_key) => Ok(Type::DhPublicKey {
                group_family: DhFamilyProto::try_from(dh_public_key.group_family)?.try_into()?,
            }),
        }
    }
}

impl TryFrom<Type> for KeyTypeProto {
    type Error = ResponseStatus;

    fn try_from(key_type: Type) -> Result<Self> {
        match key_type {
            Type::RawData => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::RawData(key_type::RawData {})),
            }),
            Type::Hmac => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Hmac(key_type::Hmac {})),
            }),
            Type::Derive => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Derive(key_type::Derive {})),
            }),
            Type::Aes => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Aes(key_type::Aes {})),
            }),
            Type::Des => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Des(key_type::Des {})),
            }),
            Type::Camellia => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Camellia(key_type::Camellia {})),
            }),
            Type::Arc4 => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Arc4(key_type::Arc4 {})),
            }),
            Type::Chacha20 => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Chacha20(key_type::Chacha20 {})),
            }),
            Type::RsaPublicKey => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::RsaPublicKey(key_type::RsaPublicKey {})),
            }),
            Type::RsaKeyPair => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::RsaKeyPair(key_type::RsaKeyPair {})),
            }),
            Type::EccKeyPair { curve_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::EccKeyPair(key_type::EccKeyPair {
                    curve_family: ecc_family_to_i32(curve_family),
                })),
            }),
            Type::EccPublicKey { curve_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::EccPublicKey(key_type::EccPublicKey {
                    curve_family: ecc_family_to_i32(curve_family),
                })),
            }),
            Type::DhKeyPair { group_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::DhKeyPair(key_type::DhKeyPair {
                    group_family: dh_family_to_i32(group_family),
                })),
            }),
            Type::DhPublicKey { group_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::DhPublicKey(key_type::DhPublicKey {
                    group_family: dh_family_to_i32(group_family),
                })),
            }),
        }
    }
}

// Attributes: from protobuf to native
impl TryFrom<KeyAttributesProto> for Attributes {
    type Error = ResponseStatus;

    fn try_from(key_attributes_proto: KeyAttributesProto) -> Result<Self> {
        Ok(Attributes {
            lifetime: Lifetime::Persistent,
            key_type: key_attributes_proto
                .key_type
                .ok_or_else(|| {
                    error!("key_type field of Attributes message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
            bits: key_attributes_proto.key_bits.try_into().or_else(|e| {
                error!("failed to convert key bits from proto. Error: {}", e);
                Err(ResponseStatus::InvalidEncoding)
            })?,
            policy: key_attributes_proto
                .key_policy
                .ok_or_else(|| {
                    error!("policy field of Attributes message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
        })
    }
}

// Attributes: from native to protobuf
impl TryFrom<Attributes> for KeyAttributesProto {
    type Error = ResponseStatus;

    fn try_from(key_attributes: Attributes) -> Result<Self> {
        Ok(KeyAttributesProto {
            key_type: Some(key_attributes.key_type.try_into()?),
            key_bits: key_attributes.bits.try_into().or_else(|e| {
                error!("failed to convert key bits to proto. Error: {}", e);
                Err(ResponseStatus::InvalidEncoding)
            })?,
            key_policy: Some(key_attributes.policy.try_into()?),
        })
    }
}

#[cfg(test)]
mod test {
    #![allow(deprecated)]
    use super::super::generated_ops::psa_algorithm::{self as algorithm_proto};
    use super::super::generated_ops::psa_key_attributes::{
        self as key_attributes_proto, KeyAttributes as KeyAttributesProto,
    };
    use crate::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
    use crate::operations::psa_key_attributes::{self, Attributes, Lifetime, Policy, UsageFlags};
    use std::convert::TryInto;

    #[test]
    fn key_attrs_to_proto() {
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

        let key_attrs_proto_expected = KeyAttributesProto {
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
                key_algorithm: Some(algorithm_proto::Algorithm {
                    variant: Some(algorithm_proto::algorithm::Variant::AsymmetricSignature(algorithm_proto::algorithm::AsymmetricSignature {
                        variant: Some(algorithm_proto::algorithm::asymmetric_signature::Variant::RsaPkcs1v15Sign(algorithm_proto::algorithm::asymmetric_signature::RsaPkcs1v15Sign {
                            hash_alg: Some(algorithm_proto::algorithm::asymmetric_signature::SignHash {
                                variant: Some(algorithm_proto::algorithm::asymmetric_signature::sign_hash::Variant::Specific(
                                    algorithm_proto::algorithm::Hash::Sha1.into(),
                                )),
                            }),
                        })),
                    }))
                }),
            }),
        };

        assert_eq!(key_attrs_proto, key_attrs_proto_expected);
    }

    #[test]
    fn key_attrs_from_proto() {
        let key_attrs_proto = KeyAttributesProto {
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
                key_algorithm: Some(algorithm_proto::Algorithm {
                    variant: Some(algorithm_proto::algorithm::Variant::AsymmetricSignature(algorithm_proto::algorithm::AsymmetricSignature {
                        variant: Some(algorithm_proto::algorithm::asymmetric_signature::Variant::RsaPkcs1v15Sign(algorithm_proto::algorithm::asymmetric_signature::RsaPkcs1v15Sign {
                            hash_alg: Some(algorithm_proto::algorithm::asymmetric_signature::SignHash {
                                variant: Some(algorithm_proto::algorithm::asymmetric_signature::sign_hash::Variant::Specific(
                                    algorithm_proto::algorithm::Hash::Sha1.into(),
                                )),
                            }),
                        })),
                    }))
                }),
            }),
        };

        let key_attrs: Attributes = key_attrs_proto.try_into().unwrap();

        let key_attrs_expected = Attributes {
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

        assert_eq!(key_attrs, key_attrs_expected);
    }
}
