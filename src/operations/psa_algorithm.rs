// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Algorithm module

use serde::{Deserialize, Serialize};

/// Enumeration of possible algorithm definitions that can be attached to
/// cryptographic keys.
/// Each variant of the enum contains a main algorithm type (which is required for
/// that variant).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl Algorithm {
    /// Check if the algorithm is a HMAC algorithm, truncated or not
    pub fn is_hmac(self) -> bool {
        match self {
            Algorithm::Mac(mac_alg) => mac_alg.is_hmac(),
            _ => false,
        }
    }
}

/// Enumeration of hash algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[allow(deprecated)]
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

impl Hash {
    /// Check if the hash alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: Hash) -> bool {
        if alg == Hash::Any {
            // Any is only authorised in key policies
            false
        } else if self == Hash::Any {
            // Any in a policy permits any hash algorithm
            true
        } else {
            self == alg
        }
    }

    /// Get the digest size output by the hash algorithm
    ///
    /// Returns `None` for `Hash::Any`
    pub fn digest_size(self) -> Option<usize> {
        match self {
            Hash::Md2 | Hash::Md4 | Hash::Md5 => Some(16),
            Hash::Ripemd160 | Hash::Sha1 => Some(20),
            Hash::Sha224 | Hash::Sha512_224 | Hash::Sha3_224 => Some(28),
            Hash::Sha256 | Hash::Sha512_256 | Hash::Sha3_256 => Some(32),
            Hash::Sha384 | Hash::Sha3_384 => Some(48),
            Hash::Sha3_512 | Hash::Sha512 => Some(64),
            Hash::Any => None,
        }
    }
}

/// Enumeration of untruncated MAC algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl FullLengthMac {
    /// Check if the alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: FullLengthMac) -> bool {
        match self {
            FullLengthMac::Hmac {
                hash_alg: hash_policy,
            } => {
                if let FullLengthMac::Hmac { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            // These ones can not be wildcard algorithms
            mac_alg => mac_alg == alg,
        }
    }
}

/// Enumeration of message authentication code algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl Mac {
    /// Check if the MAC alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: Mac) -> bool {
        match self {
            Mac::FullLength(full_length_mac_alg_policy) => {
                if let Mac::FullLength(full_length_mac_alg) = alg {
                    full_length_mac_alg_policy.is_alg_permitted(full_length_mac_alg)
                } else {
                    false
                }
            }
            Mac::Truncated {
                mac_alg: mac_alg_policy,
                mac_length: mac_length_policy,
            } => {
                if let Mac::Truncated {
                    mac_alg,
                    mac_length,
                } = alg
                {
                    mac_alg_policy.is_alg_permitted(mac_alg) && mac_length_policy == mac_length
                } else {
                    false
                }
            }
        }
    }

    /// Check if the MAC algorithm is a HMAC algorithm, truncated or not
    pub fn is_hmac(self) -> bool {
        match self {
            Mac::FullLength(FullLengthMac::Hmac { .. })
            | Mac::Truncated {
                mac_alg: FullLengthMac::Hmac { .. },
                ..
            } => true,
            _ => false,
        }
    }

    /// Check if the MAC algorithm is a construction over a block cipher
    pub fn is_block_cipher_needed(self) -> bool {
        match self {
            Mac::FullLength(FullLengthMac::CbcMac)
            | Mac::FullLength(FullLengthMac::Cmac)
            | Mac::Truncated {
                mac_alg: FullLengthMac::CbcMac,
                ..
            }
            | Mac::Truncated {
                mac_alg: FullLengthMac::Cmac,
                ..
            } => true,
            _ => false,
        }
    }
}

/// Enumeration of symmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl Cipher {
    /// Check is the cipher algorithm is a mode of a block cipher.
    pub fn is_block_cipher_mode(self) -> bool {
        match self {
            Cipher::Ctr
            | Cipher::Cfb
            | Cipher::Ofb
            | Cipher::Xts
            | Cipher::EcbNoPadding
            | Cipher::CbcNoPadding
            | Cipher::CbcPkcs7 => true,
            _ => false,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl Aead {
    /// Check if the Aead algorithm needs a block cipher
    pub fn is_block_cipher_needed(self) -> bool {
        match self {
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm)
            | Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm)
            | Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                ..
            }
            | Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                ..
            } => true,
            _ => false,
        }
    }

    /// Check if this AEAD algorithm is the (truncated or not) Chacha20-Poly1305 AEAD algorithm.
    pub fn is_chacha20_poly1305_alg(self) -> bool {
        match self {
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Chacha20Poly1305)
            | Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Chacha20Poly1305,
                ..
            } => true,
            _ => false,
        }
    }
}

/// Enumeration of asymmetric signing algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl AsymmetricSignature {
    /// Check if the alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: AsymmetricSignature) -> bool {
        match self {
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::RsaPkcs1v15Sign { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            AsymmetricSignature::RsaPss {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::RsaPss { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            AsymmetricSignature::Ecdsa {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::Ecdsa { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            AsymmetricSignature::DeterministicEcdsa {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricSignature::DeterministicEcdsa { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            // These ones can not be wildcard algorithms
            asymmetric_signature_alg => asymmetric_signature_alg == alg,
        }
    }

    /// Check if this is a RSA algorithm
    pub fn is_rsa_alg(self) -> bool {
        match self {
            AsymmetricSignature::RsaPkcs1v15Sign { .. }
            | AsymmetricSignature::RsaPkcs1v15SignRaw
            | AsymmetricSignature::RsaPss { .. } => true,
            _ => false,
        }
    }

    /// Check if this is an ECC algorithm
    pub fn is_ecc_alg(self) -> bool {
        match self {
            AsymmetricSignature::Ecdsa { .. }
            | AsymmetricSignature::EcdsaAny
            | AsymmetricSignature::DeterministicEcdsa { .. } => true,
            _ => false,
        }
    }

    /// Determines if the given hash length is compatible with the asymmetric signature scheme
    pub(crate) fn is_hash_len_permitted(self, hash_len: usize) -> bool {
        match self {
            AsymmetricSignature::EcdsaAny | AsymmetricSignature::RsaPkcs1v15SignRaw => true,
            AsymmetricSignature::DeterministicEcdsa { hash_alg }
            | AsymmetricSignature::RsaPkcs1v15Sign { hash_alg }
            | AsymmetricSignature::Ecdsa { hash_alg }
            | AsymmetricSignature::RsaPss { hash_alg } => hash_alg
                .digest_size()
                .map(|len| len == hash_len)
                .unwrap_or(false),
        }
    }
}

/// Enumeration of asymmetric encryption algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AsymmetricEncryption {
    /// RSA PKCS#1 v1.5 encryption.
    RsaPkcs1v15Crypt,
    /// RSA OAEP encryption.
    RsaOaep {
        /// A hash algorithm to use.
        hash_alg: Hash,
    },
}

impl AsymmetricEncryption {
    /// Check if the alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: AsymmetricEncryption) -> bool {
        match self {
            AsymmetricEncryption::RsaOaep {
                hash_alg: hash_policy,
            } => {
                if let AsymmetricEncryption::RsaOaep { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            // These ones can not be wildcard algorithms
            asymmetric_encryption_alg => asymmetric_encryption_alg == alg,
        }
    }
}

/// Key agreement algorithm enumeration.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RawKeyAgreement {
    /// The finite-field Diffie-Hellman (DH) key agreement algorithm.
    Ffdh,
    /// The elliptic curve Diffie-Hellman (ECDH) key agreement algorithm.
    Ecdh,
}

/// Enumeration of key agreement algorithms supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl KeyAgreement {
    /// Check if the alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: KeyAgreement) -> bool {
        match self {
            KeyAgreement::WithKeyDerivation {
                ka_alg: ka_alg_policy,
                kdf_alg: kdf_alg_policy,
            } => {
                if let KeyAgreement::WithKeyDerivation { ka_alg, kdf_alg } = alg {
                    kdf_alg_policy.is_alg_permitted(kdf_alg) && ka_alg_policy == ka_alg
                } else {
                    false
                }
            }
            // These ones can not be wildcard algorithms
            key_agreement_alg => key_agreement_alg == alg,
        }
    }
}

/// Enumeration of key derivation functions supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl KeyDerivation {
    /// Check if the alg given for a cryptographic operation is permitted to be used with this
    /// algorithm as a policy
    pub fn is_alg_permitted(self, alg: KeyDerivation) -> bool {
        match self {
            KeyDerivation::Hkdf {
                hash_alg: hash_policy,
            } => {
                if let KeyDerivation::Hkdf { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            KeyDerivation::Tls12Prf {
                hash_alg: hash_policy,
            } => {
                if let KeyDerivation::Tls12Prf { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            KeyDerivation::Tls12PskToMs {
                hash_alg: hash_policy,
            } => {
                if let KeyDerivation::Tls12PskToMs { hash_alg } = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
        }
    }
}

impl From<Hash> for Algorithm {
    fn from(alg: Hash) -> Self {
        Algorithm::Hash(alg)
    }
}
impl From<Mac> for Algorithm {
    fn from(alg: Mac) -> Self {
        Algorithm::Mac(alg)
    }
}
impl From<Cipher> for Algorithm {
    fn from(alg: Cipher) -> Self {
        Algorithm::Cipher(alg)
    }
}
impl From<Aead> for Algorithm {
    fn from(alg: Aead) -> Self {
        Algorithm::Aead(alg)
    }
}
impl From<AsymmetricSignature> for Algorithm {
    fn from(alg: AsymmetricSignature) -> Self {
        Algorithm::AsymmetricSignature(alg)
    }
}
impl From<AsymmetricEncryption> for Algorithm {
    fn from(alg: AsymmetricEncryption) -> Self {
        Algorithm::AsymmetricEncryption(alg)
    }
}
impl From<KeyAgreement> for Algorithm {
    fn from(alg: KeyAgreement) -> Self {
        Algorithm::KeyAgreement(alg)
    }
}
impl From<KeyDerivation> for Algorithm {
    fn from(alg: KeyDerivation) -> Self {
        Algorithm::KeyDerivation(alg)
    }
}
