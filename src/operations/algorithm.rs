// Copyright (c) 2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//! Algorithm module

/// Enumeration of possible algorithm definitions that can be attached to
/// cryptographic keys.
/// Each variant of the enum contains a main algorithm type (which is required for
/// that variant).
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Algorithm {
    None,
    Hash(Hash),
    Mac(Mac),
    Cipher(Cipher),
    Aead(Aead),
    AsymmetricSignature(AsymmetricSignature),
    AsymmetricEncryption(AsymmetricEncryption),
    KeyAgreement(KeyAgreement),
    KeyDerivation(KeyDerivation),
}

/// Enumeration of hash algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Hash {
    Md2,
    Md4,
    Md5,
    Ripemd160,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Any,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FullLengthMac {
    Hmac { hash_alg: Hash },
    CbcMac,
    Cmac,
}

/// Enumeration of message authentication code algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Mac {
    FullLength(FullLengthMac),
    Truncated {
        mac_alg: FullLengthMac,
        mac_length: usize,
    },
}

/// Enumeration of symmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
// StreamCipher contains "Cipher" to differentiate with the other ones that are block cipher modes.
#[allow(clippy::pub_enum_variant_names)]
pub enum Cipher {
    StreamCipher,
    Ctr,
    Cfb,
    Ofb,
    Xts,
    EcbNoPadding,
    CbcNoPadding,
    CbcPkcs7,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AeadWithDefaultLengthTag {
    Ccm,
    Gcm,
    Chacha20Poly1305,
}

/// Enumeration of authenticated encryption with additional data algorithms
/// supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Aead {
    AeadWithDefaultLengthTag(AeadWithDefaultLengthTag),
    AeadWithShortenedTag {
        aead_alg: AeadWithDefaultLengthTag,
        tag_length: usize,
    },
}

/// Enumeration of asymmetric signing algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AsymmetricSignature {
    RsaPkcs1v15Sign { hash_alg: Hash },
    RsaPkcs1v15SignRaw,
    RsaPss { hash_alg: Hash },
    Ecdsa { hash_alg: Hash },
    EcdsaAny,
    DeterministicEcdsa { hash_alg: Hash },
}

/// Enumeration of asymmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AsymmetricEncryption {
    RsaPkcs1v15Crypt,
    RsaOaep { hash_alg: Hash },
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RawKeyAgreement {
    Ffdh,
    Ecdh,
}

/// Enumeration of key agreement algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyAgreement {
    Raw(RawKeyAgreement),
    WithKeyDerivation {
        ka_alg: RawKeyAgreement,
        kdf_alg: KeyDerivation,
    },
}

/// Enumeration of key derivation functions supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyDerivation {
    Hkdf { hash_alg: Hash },
    Tls12Prf { hash_alg: Hash },
    Tls12PskToMs { hash_alg: Hash },
}
