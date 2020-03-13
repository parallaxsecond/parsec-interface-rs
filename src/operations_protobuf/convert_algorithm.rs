// Copyright (c) 2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
// Protobuf imports
use super::generated_ops::algorithm::algorithm;
use super::generated_ops::algorithm::algorithm::aead;
use super::generated_ops::algorithm::algorithm::aead::AeadWithDefaultLengthTag as AeadWithDefaultLengthTagProto;
use super::generated_ops::algorithm::algorithm::asymmetric_encryption;
use super::generated_ops::algorithm::algorithm::asymmetric_signature;
use super::generated_ops::algorithm::algorithm::key_agreement;
use super::generated_ops::algorithm::algorithm::key_agreement::Raw as RawKeyAgreementProto;
use super::generated_ops::algorithm::algorithm::key_derivation;
use super::generated_ops::algorithm::algorithm::Aead as AeadProto;
use super::generated_ops::algorithm::algorithm::AsymmetricEncryption as AsymmetricEncryptionProto;
use super::generated_ops::algorithm::algorithm::AsymmetricSignature as AsymmetricSignatureProto;
use super::generated_ops::algorithm::algorithm::Cipher as CipherProto;
use super::generated_ops::algorithm::algorithm::Hash as HashProto;
use super::generated_ops::algorithm::algorithm::KeyAgreement as KeyAgreementProto;
use super::generated_ops::algorithm::algorithm::KeyDerivation as KeyDerivationProto;
use super::generated_ops::algorithm::algorithm::Mac as MacProto;
use super::generated_ops::algorithm::algorithm::None as NoneProto;
use super::generated_ops::algorithm::algorithm::{mac, mac::FullLength as FullLengthMacProto};
use super::generated_ops::algorithm::Algorithm as AlgorithmProto;

// Native imports
use crate::operations::algorithm::{
    Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricEncryption, AsymmetricSignature, Cipher,
    FullLengthMac, Hash, KeyAgreement, KeyDerivation, Mac, RawKeyAgreement,
};

use crate::requests::{ResponseStatus, Result};
use log::error;
use std::convert::{TryFrom, TryInto};

// Hash algorithms: from protobuf to native
impl TryFrom<i32> for Hash {
    type Error = ResponseStatus;

    fn try_from(hash_val: i32) -> Result<Self> {
        let hash_val = HashProto::from_i32(hash_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid hash algorithm encoding.",
                hash_val
            );
            ResponseStatus::InvalidEncoding
        })?;
        match hash_val {
            HashProto::None => {
                error!("The None value of Hash enumeration is not allowed.");
                Err(ResponseStatus::InvalidEncoding)
            }
            HashProto::Md2 => Ok(Hash::Md2),
            HashProto::Md4 => Ok(Hash::Md4),
            HashProto::Md5 => Ok(Hash::Md5),
            HashProto::Ripemd160 => Ok(Hash::Ripemd160),
            HashProto::Sha1 => Ok(Hash::Sha1),
            HashProto::Sha224 => Ok(Hash::Sha224),
            HashProto::Sha256 => Ok(Hash::Sha256),
            HashProto::Sha384 => Ok(Hash::Sha384),
            HashProto::Sha512 => Ok(Hash::Sha512),
            HashProto::Sha512224 => Ok(Hash::Sha512_224),
            HashProto::Sha512256 => Ok(Hash::Sha512_256),
            HashProto::Sha3224 => Ok(Hash::Sha3_224),
            HashProto::Sha3256 => Ok(Hash::Sha3_256),
            HashProto::Sha3384 => Ok(Hash::Sha3_384),
            HashProto::Sha3512 => Ok(Hash::Sha3_512),
            HashProto::AnyHash => Ok(Hash::Any),
        }
    }
}

// Hash algorithms: from native to protobuf
fn hash_to_i32(hash: Hash) -> i32 {
    match hash {
        Hash::Md2 => HashProto::Md2.into(),
        Hash::Md4 => HashProto::Md4.into(),
        Hash::Md5 => HashProto::Md5.into(),
        Hash::Ripemd160 => HashProto::Ripemd160.into(),
        Hash::Sha1 => HashProto::Sha1.into(),
        Hash::Sha224 => HashProto::Sha224.into(),
        Hash::Sha256 => HashProto::Sha256.into(),
        Hash::Sha384 => HashProto::Sha384.into(),
        Hash::Sha512 => HashProto::Sha512.into(),
        Hash::Sha512_224 => HashProto::Sha512224.into(),
        Hash::Sha512_256 => HashProto::Sha512256.into(),
        Hash::Sha3_224 => HashProto::Sha3224.into(),
        Hash::Sha3_256 => HashProto::Sha3256.into(),
        Hash::Sha3_384 => HashProto::Sha3384.into(),
        Hash::Sha3_512 => HashProto::Sha3512.into(),
        Hash::Any => HashProto::AnyHash.into(),
    }
}

// FullLengthMac algorithms: from protobuf to native
impl TryFrom<FullLengthMacProto> for FullLengthMac {
    type Error = ResponseStatus;

    fn try_from(alg: FullLengthMacProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of mac::FullLength message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            mac::full_length::Variant::Hmac(hmac) => Ok(FullLengthMac::Hmac {
                hash_alg: hmac.hash_alg.try_into()?,
            }),
            mac::full_length::Variant::CbcMac(_) => Ok(FullLengthMac::CbcMac),
            mac::full_length::Variant::Cmac(_) => Ok(FullLengthMac::Cmac),
        }
    }
}

// FullLengthMac algorithms: from native to protobuf
impl TryFrom<FullLengthMac> for FullLengthMacProto {
    type Error = ResponseStatus;

    fn try_from(alg: FullLengthMac) -> Result<Self> {
        match alg {
            FullLengthMac::Hmac { hash_alg } => Ok(FullLengthMacProto {
                variant: Some(mac::full_length::Variant::Hmac(mac::full_length::Hmac {
                    hash_alg: hash_to_i32(hash_alg),
                })),
            }),
            FullLengthMac::CbcMac => Ok(FullLengthMacProto {
                variant: Some(mac::full_length::Variant::CbcMac(
                    mac::full_length::CbcMac {},
                )),
            }),
            FullLengthMac::Cmac => Ok(FullLengthMacProto {
                variant: Some(mac::full_length::Variant::Cmac(mac::full_length::Cmac {})),
            }),
        }
    }
}

// Mac algorithms: from protobuf to native
impl TryFrom<MacProto> for Mac {
    type Error = ResponseStatus;

    fn try_from(alg: MacProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of Mac message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            mac::Variant::FullLength(full_length) => Ok(Mac::FullLength(full_length.try_into()?)),
            mac::Variant::Truncated(truncated) => Ok(Mac::Truncated {
                mac_alg: truncated.mac_alg.ok_or_else(|| {
                    error!("mac_alg field of mac::Truncated message is empty.");
                    ResponseStatus::InvalidEncoding
                })?.try_into()?,
                mac_length: truncated.mac_length.try_into().or_else(|e| {
                    error!("mac_length field of mac::Truncated message can not be represented by an usize ({}).", e);
                    Err(ResponseStatus::InvalidEncoding)
                })?,
            }),
        }
    }
}

// Mac algorithms: from native to protobuf
impl TryFrom<Mac> for MacProto {
    type Error = ResponseStatus;

    fn try_from(alg: Mac) -> Result<Self> {
        match alg {
            Mac::FullLength(full_length_mac) => Ok(MacProto {
                variant: Some(mac::Variant::FullLength(full_length_mac.try_into()?)),
            }),
            Mac::Truncated {
                mac_alg,
                mac_length,
            } => Ok(MacProto {
                variant: Some(mac::Variant::Truncated(mac::Truncated {
                    mac_alg: Some(mac_alg.try_into()?),
                    mac_length: mac_length.try_into().or_else(|e| {
                        error!(
                            "mac_length field of Mac can not be represented by an u32 ({}).",
                            e
                        );
                        Err(ResponseStatus::InvalidEncoding)
                    })?,
                })),
            }),
        }
    }
}

// Cipher algorithms: from protobuf to native
impl TryFrom<i32> for Cipher {
    type Error = ResponseStatus;

    fn try_from(cipher_val: i32) -> Result<Self> {
        let cipher_val = CipherProto::from_i32(cipher_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid cipher algorithm encoding.",
                cipher_val
            );
            ResponseStatus::InvalidEncoding
        })?;
        match cipher_val {
            CipherProto::None => {
                error!("The None value of Cipher enumeration is not allowed.");
                Err(ResponseStatus::InvalidEncoding)
            }
            CipherProto::StreamCipher => Ok(Cipher::StreamCipher),
            CipherProto::Ctr => Ok(Cipher::Ctr),
            CipherProto::Cfb => Ok(Cipher::Cfb),
            CipherProto::Ofb => Ok(Cipher::Ofb),
            CipherProto::Xts => Ok(Cipher::Xts),
            CipherProto::EcbNoPadding => Ok(Cipher::EcbNoPadding),
            CipherProto::CbcNoPadding => Ok(Cipher::CbcNoPadding),
            CipherProto::CbcPkcs7 => Ok(Cipher::CbcPkcs7),
        }
    }
}

// Cipher algorithms: from native to protobuf
fn cipher_to_i32(cipher: Cipher) -> i32 {
    match cipher {
        Cipher::StreamCipher => CipherProto::StreamCipher.into(),
        Cipher::Ctr => CipherProto::Ctr.into(),
        Cipher::Cfb => CipherProto::Cfb.into(),
        Cipher::Ofb => CipherProto::Ofb.into(),
        Cipher::Xts => CipherProto::Xts.into(),
        Cipher::EcbNoPadding => CipherProto::EcbNoPadding.into(),
        Cipher::CbcNoPadding => CipherProto::CbcNoPadding.into(),
        Cipher::CbcPkcs7 => CipherProto::CbcPkcs7.into(),
    }
}

// AeadWithDefaultLengthTag algorithms: from protobuf to native
impl TryFrom<i32> for AeadWithDefaultLengthTag {
    type Error = ResponseStatus;

    fn try_from(aead_val: i32) -> Result<Self> {
        let aead_val = AeadWithDefaultLengthTagProto::from_i32(aead_val).ok_or_else(|| {
            error!("Value {} not recognised as a valid AEAD with default length tag algorithm encoding.", aead_val);
            ResponseStatus::InvalidEncoding
        })?;
        match aead_val {
            AeadWithDefaultLengthTagProto::None => {
                error!("The None value of AeadWithDefaultLengthTag enumeration is not allowed.");
                Err(ResponseStatus::InvalidEncoding)
            }
            AeadWithDefaultLengthTagProto::Ccm => Ok(AeadWithDefaultLengthTag::Ccm),
            AeadWithDefaultLengthTagProto::Gcm => Ok(AeadWithDefaultLengthTag::Gcm),
            AeadWithDefaultLengthTagProto::Chacha20Poly1305 => {
                Ok(AeadWithDefaultLengthTag::Chacha20Poly1305)
            }
        }
    }
}

// AeadWithDefaultLengthTag algorithms: from native to protobuf
fn aead_with_default_length_tag_to_i32(cipher: AeadWithDefaultLengthTag) -> i32 {
    match cipher {
        AeadWithDefaultLengthTag::Ccm => AeadWithDefaultLengthTagProto::Ccm.into(),
        AeadWithDefaultLengthTag::Gcm => AeadWithDefaultLengthTagProto::Gcm.into(),
        AeadWithDefaultLengthTag::Chacha20Poly1305 => {
            AeadWithDefaultLengthTagProto::Chacha20Poly1305.into()
        }
    }
}

// Aead algorithms: from protobuf to native
impl TryFrom<AeadProto> for Aead {
    type Error = ResponseStatus;

    fn try_from(alg: AeadProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of Aead message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            aead::Variant::AeadWithDefaultLengthTag(aead_with_default_length_tag) => Ok(Aead::AeadWithDefaultLengthTag(aead_with_default_length_tag.try_into()?)),
            aead::Variant::AeadWithShortenedTag(aead_with_shortened_tag) => Ok(Aead::AeadWithShortenedTag {
                aead_alg: aead_with_shortened_tag.aead_alg.try_into()?,
                tag_length: aead_with_shortened_tag.tag_length.try_into().or_else(|e| {
                        error!("tag_length field of aead::AeadWithShortenedTag can not be represented by an usize ({}).", e);
                        Err(ResponseStatus::InvalidEncoding)
                })?,
            }),
        }
    }
}

// Aead algorithms: from native to protobuf
impl TryFrom<Aead> for AeadProto {
    type Error = ResponseStatus;

    fn try_from(alg: Aead) -> Result<Self> {
        match alg {
            Aead::AeadWithDefaultLengthTag(aead_with_default_length_tag) => Ok(AeadProto {
                variant: Some(aead::Variant::AeadWithDefaultLengthTag(aead_with_default_length_tag_to_i32(aead_with_default_length_tag))),
            }),
            Aead::AeadWithShortenedTag { aead_alg, tag_length } => Ok(AeadProto {
                variant: Some(aead::Variant::AeadWithShortenedTag(aead::AeadWithShortenedTag {
                    aead_alg: aead_with_default_length_tag_to_i32(aead_alg),
                    tag_length: tag_length.try_into().or_else(|e| {
                        error!("tag_length field of Aead::AeadWithShortenedTag can not be represented by an u32 ({}).", e);
                        Err(ResponseStatus::InvalidEncoding)
                    })?,
                })),
            }),
        }
    }
}

// AsymmetricSignature algorithms: from protobuf to native
impl TryFrom<AsymmetricSignatureProto> for AsymmetricSignature {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricSignatureProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of Asym message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            asymmetric_signature::Variant::RsaPkcs1v15Sign(rsa_pkcs1v15_sign) => {
                Ok(AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: rsa_pkcs1v15_sign.hash_alg.try_into()?,
                })
            }
            asymmetric_signature::Variant::RsaPkcs1v15SignRaw(_) => {
                Ok(AsymmetricSignature::RsaPkcs1v15SignRaw)
            }
            asymmetric_signature::Variant::RsaPss(rsa_pss) => Ok(AsymmetricSignature::RsaPss {
                hash_alg: rsa_pss.hash_alg.try_into()?,
            }),
            asymmetric_signature::Variant::Ecdsa(ecdsa) => Ok(AsymmetricSignature::Ecdsa {
                hash_alg: ecdsa.hash_alg.try_into()?,
            }),
            asymmetric_signature::Variant::EcdsaAny(_) => Ok(AsymmetricSignature::EcdsaAny),
            asymmetric_signature::Variant::DeterministicEcdsa(deterministic_ecdsa) => {
                Ok(AsymmetricSignature::DeterministicEcdsa {
                    hash_alg: deterministic_ecdsa.hash_alg.try_into()?,
                })
            }
        }
    }
}

// AsymmetricSignature algorithms: from native to protobuf
impl TryFrom<AsymmetricSignature> for AsymmetricSignatureProto {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricSignature) -> Result<Self> {
        match alg {
            AsymmetricSignature::RsaPkcs1v15Sign { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::RsaPkcs1v15Sign(
                    asymmetric_signature::RsaPkcs1v15Sign {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
            AsymmetricSignature::RsaPkcs1v15SignRaw => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::RsaPkcs1v15SignRaw(
                    asymmetric_signature::RsaPkcs1v15SignRaw {},
                )),
            }),
            AsymmetricSignature::RsaPss { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::RsaPss(
                    asymmetric_signature::RsaPss {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
            AsymmetricSignature::Ecdsa { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::Ecdsa(
                    asymmetric_signature::Ecdsa {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
            AsymmetricSignature::EcdsaAny => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::EcdsaAny(
                    asymmetric_signature::EcdsaAny {},
                )),
            }),
            AsymmetricSignature::DeterministicEcdsa { hash_alg } => Ok(AsymmetricSignatureProto {
                variant: Some(asymmetric_signature::Variant::DeterministicEcdsa(
                    asymmetric_signature::DeterministicEcdsa {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
        }
    }
}

// AsymmetricEncryption algorithms: from protobuf to native
impl TryFrom<AsymmetricEncryptionProto> for AsymmetricEncryption {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricEncryptionProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of AsymmetricSignature message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            asymmetric_encryption::Variant::RsaPkcs1v15Crypt(_) => {
                Ok(AsymmetricEncryption::RsaPkcs1v15Crypt)
            }
            asymmetric_encryption::Variant::RsaOaep(rsa_oaep) => {
                Ok(AsymmetricEncryption::RsaOaep {
                    hash_alg: rsa_oaep.hash_alg.try_into()?,
                })
            }
        }
    }
}

// AsymmetricEncryption algorithms: from native to protobuf
impl TryFrom<AsymmetricEncryption> for AsymmetricEncryptionProto {
    type Error = ResponseStatus;

    fn try_from(alg: AsymmetricEncryption) -> Result<Self> {
        match alg {
            AsymmetricEncryption::RsaPkcs1v15Crypt => Ok(AsymmetricEncryptionProto {
                variant: Some(asymmetric_encryption::Variant::RsaPkcs1v15Crypt(
                    asymmetric_encryption::RsaPkcs1v15Crypt {},
                )),
            }),
            AsymmetricEncryption::RsaOaep { hash_alg } => Ok(AsymmetricEncryptionProto {
                variant: Some(asymmetric_encryption::Variant::RsaOaep(
                    asymmetric_encryption::RsaOaep {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
        }
    }
}

// RawKeyAgreement algorithms: from protobuf to native
impl TryFrom<i32> for RawKeyAgreement {
    type Error = ResponseStatus;

    fn try_from(raw_key_agreement_val: i32) -> Result<Self> {
        let raw_key_agreement_val = RawKeyAgreementProto::from_i32(raw_key_agreement_val)
            .ok_or_else(|| {
                error!(
                    "Value {} not recognised as a valid raw key agreement algorithm encoding.",
                    raw_key_agreement_val
                );
                ResponseStatus::InvalidEncoding
            })?;
        match raw_key_agreement_val {
            RawKeyAgreementProto::None => {
                error!("The None value of RawKeyAgreement enumeration is not allowed.");
                Err(ResponseStatus::InvalidEncoding)
            }
            RawKeyAgreementProto::Ffdh => Ok(RawKeyAgreement::Ffdh),
            RawKeyAgreementProto::Ecdh => Ok(RawKeyAgreement::Ecdh),
        }
    }
}

// RawKeyAgreement algorithms: from native to protobuf
fn raw_key_agreement_to_i32(raw_key_agreement: RawKeyAgreement) -> i32 {
    match raw_key_agreement {
        RawKeyAgreement::Ffdh => RawKeyAgreementProto::Ffdh.into(),
        RawKeyAgreement::Ecdh => RawKeyAgreementProto::Ecdh.into(),
    }
}

// KeyAgreement algorithms: from protobuf to native
impl TryFrom<KeyAgreementProto> for KeyAgreement {
    type Error = ResponseStatus;

    fn try_from(alg: KeyAgreementProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of KeyAgreement message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            key_agreement::Variant::Raw(raw) => Ok(KeyAgreement::Raw(raw.try_into()?)),
            key_agreement::Variant::WithKeyDerivation(with_key_derivation) => Ok(KeyAgreement::WithKeyDerivation {
                ka_alg: with_key_derivation.ka_alg.try_into()?,
                kdf_alg: with_key_derivation.kdf_alg.ok_or_else(|| {
                    error!("kdf_alg field of key_agreement::WithKeyDerivation message is empty.");
                    ResponseStatus::InvalidEncoding
                })?.try_into()?,
            }),
        }
    }
}

// KeyAgreement algorithms: from native to protobuf
impl TryFrom<KeyAgreement> for KeyAgreementProto {
    type Error = ResponseStatus;

    fn try_from(alg: KeyAgreement) -> Result<Self> {
        match alg {
            KeyAgreement::Raw(raw_key_agreement) => Ok(KeyAgreementProto {
                variant: Some(key_agreement::Variant::Raw(raw_key_agreement_to_i32(
                    raw_key_agreement,
                ))),
            }),
            KeyAgreement::WithKeyDerivation { ka_alg, kdf_alg } => Ok(KeyAgreementProto {
                variant: Some(key_agreement::Variant::WithKeyDerivation(
                    key_agreement::WithKeyDerivation {
                        ka_alg: raw_key_agreement_to_i32(ka_alg),
                        kdf_alg: Some(kdf_alg.try_into()?),
                    },
                )),
            }),
        }
    }
}

// KeyDerivation algorithms: from protobuf to native
impl TryFrom<KeyDerivationProto> for KeyDerivation {
    type Error = ResponseStatus;

    fn try_from(alg: KeyDerivationProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of KeyDerivation message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            key_derivation::Variant::Hkdf(hkdf) => Ok(KeyDerivation::Hkdf {
                hash_alg: hkdf.hash_alg.try_into()?,
            }),
            key_derivation::Variant::Tls12Prf(tls12_prf) => Ok(KeyDerivation::Tls12Prf {
                hash_alg: tls12_prf.hash_alg.try_into()?,
            }),
            key_derivation::Variant::Tls12PskToMs(tls12_psk_to_ms) => {
                Ok(KeyDerivation::Tls12PskToMs {
                    hash_alg: tls12_psk_to_ms.hash_alg.try_into()?,
                })
            }
        }
    }
}

// KeyDerivation algorithms: from native to protobuf
impl TryFrom<KeyDerivation> for KeyDerivationProto {
    type Error = ResponseStatus;

    fn try_from(alg: KeyDerivation) -> Result<Self> {
        match alg {
            KeyDerivation::Hkdf { hash_alg } => Ok(KeyDerivationProto {
                variant: Some(key_derivation::Variant::Hkdf(key_derivation::Hkdf {
                    hash_alg: hash_to_i32(hash_alg),
                })),
            }),
            KeyDerivation::Tls12Prf { hash_alg } => Ok(KeyDerivationProto {
                variant: Some(key_derivation::Variant::Tls12Prf(
                    key_derivation::Tls12Prf {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
            KeyDerivation::Tls12PskToMs { hash_alg } => Ok(KeyDerivationProto {
                variant: Some(key_derivation::Variant::Tls12PskToMs(
                    key_derivation::Tls12PskToMs {
                        hash_alg: hash_to_i32(hash_alg),
                    },
                )),
            }),
        }
    }
}

// Algorithm: from protobug to native
impl TryFrom<AlgorithmProto> for Algorithm {
    type Error = ResponseStatus;

    fn try_from(alg: AlgorithmProto) -> Result<Self> {
        match alg.variant.ok_or_else(|| {
            error!("variant field of Algorithm message is empty.");
            ResponseStatus::InvalidEncoding
        })? {
            algorithm::Variant::None(_) => Ok(Algorithm::None),
            algorithm::Variant::Hash(hash) => Ok(Algorithm::Hash(hash.try_into()?)),
            algorithm::Variant::Mac(mac) => Ok(Algorithm::Mac(mac.try_into()?)),
            algorithm::Variant::Cipher(cipher) => Ok(Algorithm::Cipher(cipher.try_into()?)),
            algorithm::Variant::Aead(aead) => Ok(Algorithm::Aead(aead.try_into()?)),
            algorithm::Variant::AsymmetricSignature(asymmetric_signature) => Ok(
                Algorithm::AsymmetricSignature(asymmetric_signature.try_into()?),
            ),
            algorithm::Variant::AsymmetricEncryption(asymmetric_encryption) => Ok(
                Algorithm::AsymmetricEncryption(asymmetric_encryption.try_into()?),
            ),
            algorithm::Variant::KeyAgreement(key_agreement) => {
                Ok(Algorithm::KeyAgreement(key_agreement.try_into()?))
            }
            algorithm::Variant::KeyDerivation(key_derivation) => {
                Ok(Algorithm::KeyDerivation(key_derivation.try_into()?))
            }
        }
    }
}

// Algorithm: from native to protobuf
impl TryFrom<Algorithm> for AlgorithmProto {
    type Error = ResponseStatus;

    fn try_from(alg: Algorithm) -> Result<Self> {
        match alg {
            Algorithm::None => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::None(NoneProto {})),
            }),
            Algorithm::Hash(hash) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Hash(hash_to_i32(hash))),
            }),
            Algorithm::Mac(mac) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Mac(mac.try_into()?)),
            }),
            Algorithm::Cipher(cipher) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Cipher(cipher_to_i32(cipher))),
            }),
            Algorithm::Aead(aead) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::Aead(aead.try_into()?)),
            }),
            Algorithm::AsymmetricSignature(asymmetric_signature) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::AsymmetricSignature(
                    asymmetric_signature.try_into()?,
                )),
            }),
            Algorithm::AsymmetricEncryption(asymmetric_encryption) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::AsymmetricEncryption(
                    asymmetric_encryption.try_into()?,
                )),
            }),
            Algorithm::KeyAgreement(key_agreement) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::KeyAgreement(key_agreement.try_into()?)),
            }),
            Algorithm::KeyDerivation(key_derivation) => Ok(AlgorithmProto {
                variant: Some(algorithm::Variant::KeyDerivation(
                    key_derivation.try_into()?,
                )),
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::algorithm::{
        self as algorithm_proto, Algorithm as AlgorithmProto,
    };
    use crate::operations::algorithm::{Algorithm, AsymmetricSignature, Hash};
    use std::convert::TryInto;

    #[test]
    fn sign_algo_from_proto() {
        let proto_sign = algorithm_proto::Algorithm {
            variant: Some(algorithm_proto::algorithm::Variant::AsymmetricSignature(
                algorithm_proto::algorithm::AsymmetricSignature {
                    variant: Some(
                        algorithm_proto::algorithm::asymmetric_signature::Variant::RsaPkcs1v15Sign(
                            algorithm_proto::algorithm::asymmetric_signature::RsaPkcs1v15Sign {
                                hash_alg: algorithm_proto::algorithm::Hash::Sha1.into(),
                            },
                        ),
                    ),
                },
            )),
        };

        let sign: Algorithm = proto_sign.try_into().unwrap();
        let sign_expected = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1,
        });

        assert_eq!(sign, sign_expected);
    }

    #[test]
    fn sign_algo_to_proto() {
        let sign = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1,
        });

        let proto_sign: AlgorithmProto = sign.try_into().unwrap();
        let proto_sign_expected = algorithm_proto::Algorithm {
            variant: Some(algorithm_proto::algorithm::Variant::AsymmetricSignature(
                algorithm_proto::algorithm::AsymmetricSignature {
                    variant: Some(
                        algorithm_proto::algorithm::asymmetric_signature::Variant::RsaPkcs1v15Sign(
                            algorithm_proto::algorithm::asymmetric_signature::RsaPkcs1v15Sign {
                                hash_alg: algorithm_proto::algorithm::Hash::Sha1.into(),
                            },
                        ),
                    ),
                },
            )),
        };

        assert_eq!(proto_sign, proto_sign_expected);
    }
}
