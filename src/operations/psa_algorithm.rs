// Copyright (c) 2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//! Algorithm module

/// Enumeration of possible algorithm definitions that can be attached to
/// cryptographic keys.
/// Each variant of the enum contains a main algorithm type (which is required for
/// that variant).
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Algorithm {
    /// An invalid algorithm identifier value.
    /// `None` does not allow any cryptographic operation with the key. The key can still be
    /// used for non-cryptographic actions such as exporting, if permitted by the usage flags.
    None,
    /// Hash algorithm.
    Hash(Hash),
    /// MAC algorithm.
    Mac(Mac),
    /// Symmetric Cipher algorithm.
    Cipher(Cipher),
    /// Authenticated Encryption with Associated Data (AEAD) algorithm.
    Aead(Aead),
    /// Public-key signature algorithm.
    AsymmetricSignature(AsymmetricSignature),
    /// Public-key encryption algorithm.
    AsymmetricEncryption(AsymmetricEncryption),
    /// Key agreement algorithm.
    KeyAgreement(KeyAgreement),
    /// Key derivation algorithm.
    KeyDerivation(KeyDerivation),
}

/// Enumeration of hash algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Hash {
    /// MD2
    #[deprecated = "The MD2 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Md2,
    /// MD4
    #[deprecated = "The MD4 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Md4,
    /// MD5
    #[deprecated = "The MD5 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Md5,
    /// RIPEMD-160
    Ripemd160,
    /// SHA-1
    #[deprecated = "The SHA-1 hash is weak and deprecated and is only recommended for use in legacy protocols."]
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// SHA-512/224
    Sha512_224,
    /// SHA-512/256
    Sha512_256,
    /// SHA3-224
    Sha3_224,
    /// SHA3-256
    Sha3_256,
    /// SHA3-384
    Sha3_384,
    /// SHA3-512
    Sha3_512,
    /// In a hash-and-sign algorithm policy, allow any hash algorithm. This value must not be used
    /// to build an algorithm specification to perform an operation. It is only valid to build
    /// policies.
    Any,
}

/// Enumeration of untruncated MAC algorithms.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FullLengthMac {
    /// HMAC algorithm
    Hmac {
        /// Hash algorithm to use.
        hash_alg: Hash,
    },
    /// The CBC-MAC construction over a block cipher.
    CbcMac,
    /// The CMAC construction over a block cipher.
    Cmac,
}

/// Enumeration of message authentication code algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Mac {
    /// Untruncated MAC algorithm
    FullLength(FullLengthMac),
    /// Truncated MAC algorithm
    Truncated {
        /// The MAC algorithm to truncate.
        mac_alg: FullLengthMac,
        /// Desired length of the truncated MAC in bytes.
        mac_length: usize,
    },
}

/// Enumeration of symmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
// StreamCipher contains "Cipher" to differentiate with the other ones that are block cipher modes.
#[allow(clippy::pub_enum_variant_names)]
pub enum Cipher {
    /// The stream cipher mode of a stream cipher algorithm.
    StreamCipher,
    /// A stream cipher built using the Counter (CTR) mode of a block cipher.
    Ctr,
    /// A stream cipher built using the Cipher Feedback (CFB) mode of a block cipher.
    Cfb,
    /// A stream cipher built using the Output Feedback (OFB) mode of a block cipher.
    Ofb,
    /// The XTS cipher mode of a block cipher.
    Xts,
    /// The Electronic Code Book (ECB) mode of a block cipher, with no padding.
    EcbNoPadding,
    /// The Cipher Block Chaining (CBC) mode of a block cipher, with no padding.
    CbcNoPadding,
    /// The Cipher Block Chaining (CBC) mode of a block cipher, with PKCS#7 padding.
    CbcPkcs7,
}

#[derive(Copy, Clone, Debug, PartialEq)]
/// AEAD algorithm with default length tag enumeration
pub enum AeadWithDefaultLengthTag {
    /// The CCM authenticated encryption algorithm.
    Ccm,
    /// The GCM authenticated encryption algorithm.
    Gcm,
    /// The Chacha20-Poly1305 AEAD algorithm.
    Chacha20Poly1305,
}

/// Enumeration of authenticated encryption with additional data algorithms
/// supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Aead {
    /// AEAD algorithm with a default length tag
    AeadWithDefaultLengthTag(AeadWithDefaultLengthTag),
    /// AEAD algorithm with a shortened tag.
    AeadWithShortenedTag {
        /// An AEAD algorithm.
        aead_alg: AeadWithDefaultLengthTag,
        /// Desired length of the authentication tag in bytes.
        tag_length: usize,
    },
}

/// Enumeration of asymmetric signing algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AsymmetricSignature {
    /// RSA PKCS#1 v1.5 signature with hashing.
    RsaPkcs1v15Sign {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
    /// Raw PKCS#1 v1.5 signature.
    RsaPkcs1v15SignRaw,
    /// RSA PSS signature with hashing.
    RsaPss {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
    /// ECDSA signature with hashing.
    Ecdsa {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
    /// ECDSA signature without hashing.
    EcdsaAny,
    /// Deterministic ECDSA signature with hashing.
    DeterministicEcdsa {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
}

/// Enumeration of asymmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AsymmetricEncryption {
    /// RSA PKCS#1 v1.5 encryption.
    RsaPkcs1v15Crypt,
    /// RSA OAEP encryption.
    RsaOaep {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
}

/// Key agreement algorithm enumeration.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RawKeyAgreement {
    /// The finite-field Diffie-Hellman (DH) key agreement algorithm.
    Ffdh,
    /// The elliptic curve Diffie-Hellman (ECDH) key agreement algorithm.
    Ecdh,
}

/// Enumeration of key agreement algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyAgreement {
    /// Key agreement only algorithm.
    Raw(RawKeyAgreement),
    /// Build a combined algorithm that chains a key agreement with a key derivation.
    WithKeyDerivation {
        /// A key agreement algorithm.
        ka_alg: RawKeyAgreement,
        /// A key derivation algorithm.
        kdf_alg: KeyDerivation,
    },
}

/// Enumeration of key derivation functions supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyDerivation {
    /// HKDF algorithm.
    Hkdf {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
    /// TLS-1.2 PRF algorithm.
    Tls12Prf {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
    /// TLS-1.2 PSK-to-MasterSecret algorithm.
    Tls12PskToMs {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
}
