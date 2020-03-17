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
// Protobuf imports
use super::generated_ops::key_attributes::key_type;
use super::generated_ops::key_attributes::{
    key_type::DhFamily as DhFamilyProto, key_type::EccFamily as EccFamilyProto,
    KeyAttributes as KeyAttributesProto, KeyPolicy as KeyPolicyProto, KeyType as KeyTypeProto,
    UsageFlags as UsageFlagsProto,
};
// Native imports
use crate::operations::algorithm::Algorithm;
use crate::operations::key_attributes::{
    DhFamily, EccFamily, KeyAttributes, KeyPolicy, KeyType, UsageFlags,
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

// KeyPolicy: from protobuf to native
impl TryFrom<KeyPolicyProto> for KeyPolicy {
    type Error = ResponseStatus;

    fn try_from(key_policy_proto: KeyPolicyProto) -> Result<Self> {
        let key_algorithm: Algorithm = key_policy_proto
            .key_algorithm
            .ok_or_else(|| {
                error!("key_algorithm field of KeyPolicy message is empty.");
                ResponseStatus::InvalidEncoding
            })?
            .try_into()?;
        Ok(KeyPolicy {
            key_usage_flags: key_policy_proto
                .key_usage_flags
                .ok_or_else(|| {
                    error!("key_usage_flags field of KeyPolicy message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
            key_algorithm,
        })
    }
}

// KeyPolicy: from native to protobuf
impl TryFrom<KeyPolicy> for KeyPolicyProto {
    type Error = ResponseStatus;

    fn try_from(key_policy: KeyPolicy) -> Result<Self> {
        Ok(KeyPolicyProto {
            key_usage_flags: Some(key_policy.key_usage_flags.try_into()?),
            key_algorithm: Some(key_policy.key_algorithm.try_into()?),
        })
    }
}

// EccFamily: from protobuf to native
impl TryFrom<i32> for EccFamily {
    type Error = ResponseStatus;

    fn try_from(ecc_family_val: i32) -> Result<Self> {
        let ecc_family_val = EccFamilyProto::from_i32(ecc_family_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid ECC family encoding.",
                ecc_family_val
            );
            ResponseStatus::InvalidEncoding
        })?;
        match ecc_family_val {
            EccFamilyProto::None => {
                error!("The None value of EccFamily enumeration is not allowed.");
                Err(ResponseStatus::InvalidEncoding)
            }
            EccFamilyProto::SecpK1 => Ok(EccFamily::SecpK1),
            EccFamilyProto::SecpR1 => Ok(EccFamily::SecpR1),
            EccFamilyProto::SecpR2 => Ok(EccFamily::SecpR2),
            EccFamilyProto::SectK1 => Ok(EccFamily::SectK1),
            EccFamilyProto::SectR1 => Ok(EccFamily::SectR1),
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
        EccFamily::SecpR2 => EccFamilyProto::SecpR2.into(),
        EccFamily::SectK1 => EccFamilyProto::SectK1.into(),
        EccFamily::SectR1 => EccFamilyProto::SectR1.into(),
        EccFamily::SectR2 => EccFamilyProto::SectR2.into(),
        EccFamily::BrainpoolPR1 => EccFamilyProto::BrainpoolPR1.into(),
        EccFamily::Frp => EccFamilyProto::Frp.into(),
        EccFamily::Montgomery => EccFamilyProto::Montgomery.into(),
    }
}

// DhFamily: from protobuf to native
impl TryFrom<i32> for DhFamily {
    type Error = ResponseStatus;

    fn try_from(dh_family_val: i32) -> Result<Self> {
        let dh_family_val = DhFamilyProto::from_i32(dh_family_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid DH family encoding.",
                dh_family_val
            );
            ResponseStatus::InvalidEncoding
        })?;
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

impl TryFrom<KeyTypeProto> for KeyType {
    type Error = ResponseStatus;

    fn try_from(key_type_proto: KeyTypeProto) -> Result<Self> {
        match key_type_proto.variant.ok_or_else(|| {
            error!("variant field of KeyType message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            key_type::Variant::RawData(_) => Ok(KeyType::RawData),
            key_type::Variant::Hmac(_) => Ok(KeyType::Hmac),
            key_type::Variant::Derive(_) => Ok(KeyType::Derive),
            key_type::Variant::Aes(_) => Ok(KeyType::Aes),
            key_type::Variant::Des(_) => Ok(KeyType::Des),
            key_type::Variant::Camellia(_) => Ok(KeyType::Camellia),
            key_type::Variant::Arc4(_) => Ok(KeyType::Arc4),
            key_type::Variant::Chacha20(_) => Ok(KeyType::Chacha20),
            key_type::Variant::RsaPublicKey(_) => Ok(KeyType::RsaPublicKey),
            key_type::Variant::RsaKeyPair(_) => Ok(KeyType::RsaKeyPair),
            key_type::Variant::EccKeyPair(ecc_key_pair) => Ok(KeyType::EccKeyPair {
                curve_family: ecc_key_pair.curve_family.try_into()?,
            }),
            key_type::Variant::EccPublicKey(ecc_public_key) => Ok(KeyType::EccPublicKey {
                curve_family: ecc_public_key.curve_family.try_into()?,
            }),
            key_type::Variant::DhKeyPair(dh_key_pair) => Ok(KeyType::DhKeyPair {
                group_family: dh_key_pair.group_family.try_into()?,
            }),
            key_type::Variant::DhPublicKey(dh_public_key) => Ok(KeyType::DhPublicKey {
                group_family: dh_public_key.group_family.try_into()?,
            }),
        }
    }
}

impl TryFrom<KeyType> for KeyTypeProto {
    type Error = ResponseStatus;

    fn try_from(key_type: KeyType) -> Result<Self> {
        match key_type {
            KeyType::RawData => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::RawData(key_type::RawData {})),
            }),
            KeyType::Hmac => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Hmac(key_type::Hmac {})),
            }),
            KeyType::Derive => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Derive(key_type::Derive {})),
            }),
            KeyType::Aes => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Aes(key_type::Aes {})),
            }),
            KeyType::Des => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Des(key_type::Des {})),
            }),
            KeyType::Camellia => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Camellia(key_type::Camellia {})),
            }),
            KeyType::Arc4 => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Arc4(key_type::Arc4 {})),
            }),
            KeyType::Chacha20 => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::Chacha20(key_type::Chacha20 {})),
            }),
            KeyType::RsaPublicKey => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::RsaPublicKey(key_type::RsaPublicKey {})),
            }),
            KeyType::RsaKeyPair => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::RsaKeyPair(key_type::RsaKeyPair {})),
            }),
            KeyType::EccKeyPair { curve_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::EccKeyPair(key_type::EccKeyPair {
                    curve_family: ecc_family_to_i32(curve_family),
                })),
            }),
            KeyType::EccPublicKey { curve_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::EccPublicKey(key_type::EccPublicKey {
                    curve_family: ecc_family_to_i32(curve_family),
                })),
            }),
            KeyType::DhKeyPair { group_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::DhKeyPair(key_type::DhKeyPair {
                    group_family: dh_family_to_i32(group_family),
                })),
            }),
            KeyType::DhPublicKey { group_family } => Ok(KeyTypeProto {
                variant: Some(key_type::Variant::DhPublicKey(key_type::DhPublicKey {
                    group_family: dh_family_to_i32(group_family),
                })),
            }),
        }
    }
}

// KeyAttributes: from protobuf to native
impl TryFrom<KeyAttributesProto> for KeyAttributes {
    type Error = ResponseStatus;

    fn try_from(key_attributes_proto: KeyAttributesProto) -> Result<Self> {
        Ok(KeyAttributes {
            key_type: key_attributes_proto
                .key_type
                .ok_or_else(|| {
                    error!("key_type field of KeyAttributes message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
            key_bits: key_attributes_proto.key_bits,
            key_policy: key_attributes_proto
                .key_policy
                .ok_or_else(|| {
                    error!("key_policy field of KeyAttributes message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
        })
    }
}

// KeyAttributes: from native to protobuf
impl TryFrom<KeyAttributes> for KeyAttributesProto {
    type Error = ResponseStatus;

    fn try_from(key_attributes: KeyAttributes) -> Result<Self> {
        Ok(KeyAttributesProto {
            key_type: Some(key_attributes.key_type.try_into()?),
            key_bits: key_attributes.key_bits,
            key_policy: Some(key_attributes.key_policy.try_into()?),
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::algorithm::{self as algorithm_proto};
    use super::super::generated_ops::key_attributes::{
        self as key_attributes_proto, KeyAttributes as KeyAttributesProto,
    };
    use crate::operations::algorithm::{Algorithm, AsymmetricSignature, Hash};
    use crate::operations::key_attributes::{self, KeyAttributes, KeyPolicy, UsageFlags};
    use std::convert::TryInto;

    #[test]
    fn key_attrs_to_proto() {
        let key_attrs = KeyAttributes {
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
                            hash_alg: algorithm_proto::algorithm::Hash::Sha1.into(),
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
                            hash_alg: algorithm_proto::algorithm::Hash::Sha1.into(),
                        })),
                    }))
                }),
            }),
        };

        let key_attrs: KeyAttributes = key_attrs_proto.try_into().unwrap();

        let key_attrs_expected = KeyAttributes {
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
        };

        assert_eq!(key_attrs, key_attrs_expected);
    }
}
