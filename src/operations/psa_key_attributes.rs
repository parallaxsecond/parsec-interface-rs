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
//! # Key attributes
//!
//! The key attributes are used for some key management operations and also on cryptographic
//! operations to make sure that the key has the correct policy.

use crate::operations::psa_algorithm::{Algorithm, Cipher};
use crate::requests::{ResponseStatus, Result};
use log::error;
use serde::{Deserialize, Serialize};

/// Native definition of the attributes needed to fully describe
/// a cryptographic key.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyAttributes {
    /// Intrinsic category and type of a key
    pub key_type: KeyType,
    /// Size of a key in bits
    pub key_bits: u32,
    /// Policy restricting the permitted usage of the key
    pub key_policy: KeyPolicy,
}

impl KeyAttributes {
    /// Check if a key has permission to be exported
    pub fn is_exportable(self) -> bool {
        self.key_policy.key_usage_flags.export
    }

    /// Check export in a faillible way
    pub fn can_export(self) -> Result<()> {
        if self.is_exportable() {
            Ok(())
        } else {
            error!("Key attributes do not permit exporting key.");
            Err(ResponseStatus::PsaErrorNotPermitted)
        }
    }

    /// Check if a key has permission to sign a message hash
    pub fn is_hash_signable(self) -> bool {
        self.key_policy.key_usage_flags.sign_hash
    }

    /// Check hash signing permission in a faillible way
    pub fn can_sign_hash(self) -> Result<()> {
        if self.is_hash_signable() {
            Ok(())
        } else {
            error!("Key attributes do not permit signing hashes.");
            Err(ResponseStatus::PsaErrorNotPermitted)
        }
    }

    /// Check if a key has permission to verify a message hash
    pub fn is_hash_verifiable(self) -> bool {
        self.key_policy.key_usage_flags.verify_hash
    }

    /// Check hash signing permission in a faillible way
    pub fn can_verify_hash(self) -> Result<()> {
        if self.is_hash_verifiable() {
            Ok(())
        } else {
            error!("Key attributes do not permit verifying hashes.");
            Err(ResponseStatus::PsaErrorNotPermitted)
        }
    }

    /// Check if the alg given for a cryptographic operation is permitted to be used with the key
    pub fn is_alg_permitted(self, alg: Algorithm) -> bool {
        match self.key_policy.key_algorithm {
            Algorithm::None => false,
            Algorithm::Hash(hash_policy) => {
                if let Algorithm::Hash(hash_alg) = alg {
                    hash_policy.is_alg_permitted(hash_alg)
                } else {
                    false
                }
            }
            Algorithm::Mac(mac_policy) => {
                if let Algorithm::Mac(mac_alg) = alg {
                    mac_policy.is_alg_permitted(mac_alg)
                } else {
                    false
                }
            }
            Algorithm::AsymmetricSignature(asymmetric_signature_alg_policy) => {
                if let Algorithm::AsymmetricSignature(asymmetric_signature_alg) = alg {
                    asymmetric_signature_alg_policy.is_alg_permitted(asymmetric_signature_alg)
                } else {
                    false
                }
            }
            Algorithm::AsymmetricEncryption(asymmetric_encryption_alg_policy) => {
                if let Algorithm::AsymmetricEncryption(asymmetric_encryption_alg) = alg {
                    asymmetric_encryption_alg_policy.is_alg_permitted(asymmetric_encryption_alg)
                } else {
                    false
                }
            }
            Algorithm::KeyDerivation(key_derivation_alg_policy) => {
                if let Algorithm::KeyDerivation(key_derivation_alg) = alg {
                    key_derivation_alg_policy.is_alg_permitted(key_derivation_alg)
                } else {
                    false
                }
            }
            Algorithm::KeyAgreement(key_agreement_alg_policy) => {
                if let Algorithm::KeyAgreement(key_agreement_alg) = alg {
                    key_agreement_alg_policy.is_alg_permitted(key_agreement_alg)
                } else {
                    false
                }
            }
            // These ones can not be wildcard algorithms: it is sufficient to just check for
            // equality.
            Algorithm::Cipher(_) | Algorithm::Aead(_) => self.key_policy.key_algorithm == alg,
        }
    }

    /// Check if alg is permitted in a faillible way
    pub fn permits_alg(self, alg: Algorithm) -> Result<()> {
        if self.is_alg_permitted(alg) {
            Ok(())
        } else {
            error!("Key attributes do not permit specified algorithm.");
            Err(ResponseStatus::PsaErrorNotPermitted)
        }
    }

    /// Check if the alg given for a cryptographic operation is compatible with the type of the
    /// key
    pub fn is_compatible_with_alg(self, alg: Algorithm) -> bool {
        match self.key_type {
            KeyType::RawData => false,
            KeyType::Hmac => alg.is_hmac(),
            KeyType::Derive => {
                if let Algorithm::KeyDerivation(_) = alg {
                    true
                } else {
                    false
                }
            }
            KeyType::Aes | KeyType::Camellia => {
                if let Algorithm::Mac(mac_alg) = alg {
                    mac_alg.is_block_cipher_needed()
                } else if let Algorithm::Cipher(cipher_alg) = alg {
                    cipher_alg.is_block_cipher_mode()
                } else if let Algorithm::Aead(aead_alg) = alg {
                    aead_alg.is_block_cipher_needed()
                } else {
                    false
                }
            }
            KeyType::Des => {
                if let Algorithm::Mac(mac_alg) = alg {
                    mac_alg.is_block_cipher_needed()
                } else if let Algorithm::Cipher(cipher_alg) = alg {
                    cipher_alg.is_block_cipher_mode()
                } else {
                    false
                }
            }
            KeyType::Arc4 => alg == Algorithm::Cipher(Cipher::StreamCipher),
            KeyType::Chacha20 => {
                if alg == Algorithm::Cipher(Cipher::StreamCipher) {
                    true
                } else if let Algorithm::Aead(aead_alg) = alg {
                    aead_alg.is_chacha20_poly1305_alg()
                } else {
                    false
                }
            }
            KeyType::RsaPublicKey | KeyType::RsaKeyPair => {
                if let Algorithm::AsymmetricSignature(sign_alg) = alg {
                    sign_alg.is_rsa_alg()
                } else if let Algorithm::AsymmetricEncryption(_) = alg {
                    true
                } else {
                    false
                }
            }
            KeyType::EccKeyPair { .. } | KeyType::EccPublicKey { .. } => {
                if let Algorithm::AsymmetricSignature(sign_alg) = alg {
                    sign_alg.is_ecc_alg()
                } else {
                    false
                }
            }
            KeyType::DhKeyPair { .. } | KeyType::DhPublicKey { .. } => {
                if let Algorithm::KeyAgreement(_) = alg {
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Check if alg is compatible in a faillible way
    pub fn compatible_with_alg(self, alg: Algorithm) -> Result<()> {
        if self.is_compatible_with_alg(alg) {
            Ok(())
        } else {
            error!("Key attributes are not compatible with specified algorithm.");
            Err(ResponseStatus::PsaErrorNotPermitted)
        }
    }
}

/// Enumeration of key types supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    /// Not a valid key type for any cryptographic operation but can be used to store arbitrary
    /// data in the key store.
    RawData,
    /// HMAC key.
    Hmac,
    /// A secret key for derivation.
    Derive,
    /// Key for a cipher, AEAD or MAC algorithm based on the AES block cipher.
    Aes,
    /// Key for a cipher or MAC algorithm based on DES or 3DES (Triple-DES).
    Des,
    /// Key for a cipher, AEAD or MAC algorithm based on the Camellia block cipher.
    Camellia,
    /// Key for the RC4 stream cipher.
    Arc4,
    /// Key for the ChaCha20 stream cipher or the Chacha20-Poly1305 AEAD algorithm.
    Chacha20,
    /// RSA public key.
    RsaPublicKey,
    /// RSA key pair: both the private and public key.
    RsaKeyPair,
    /// Elliptic curve key pair: both the private and public key.
    EccKeyPair {
        /// ECC curve family to use.
        curve_family: EccFamily,
    },
    /// Elliptic curve public key.
    EccPublicKey {
        /// ECC curve family to use.
        curve_family: EccFamily,
    },
    /// Diffie-Hellman key pair: both the private key and public key.
    DhKeyPair {
        /// Diffie-Hellman group family to use.
        group_family: DhFamily,
    },
    /// Diffie-Hellman public key.
    DhPublicKey {
        /// Diffie-Hellman group family to use.
        group_family: DhFamily,
    },
}

impl KeyType {
    /// Checks if a key type is ECC key pair with any curve family inside.
    pub fn is_ecc_key_pair(self) -> bool {
        match self {
            KeyType::EccKeyPair { .. } => true,
            _ => false,
        }
    }

    /// Checks if a key type is ECC public key with any curve family inside.
    pub fn is_ecc_public_key(self) -> bool {
        match self {
            KeyType::EccPublicKey { .. } => true,
            _ => false,
        }
    }

    /// Checks if a key type is DH public key with any group family inside.
    pub fn is_dh_public_key(self) -> bool {
        match self {
            KeyType::DhPublicKey { .. } => true,
            _ => false,
        }
    }

    /// Checks if a key type is DH key pair with any group family inside.
    pub fn is_dh_key_pair(self) -> bool {
        match self {
            KeyType::DhKeyPair { .. } => true,
            _ => false,
        }
    }
}

/// Enumeration of elliptic curve families supported. They are needed to create an ECC key.
/// The specific curve used for each family is given by the `key_bits` field of the key attributes.
/// See the book for more details.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EccFamily {
    /// SEC Koblitz curves over prime fields.
    /// This family comprises the following curves:
    ///   * secp192k1: `key_bits` = 192
    ///   * secp224k1: `key_bits` = 225
    ///   * secp256k1: `key_bits` = 256
    SecpK1,
    /// SEC random curves over prime fields.
    /// This family comprises the following curves:
    ///   * secp192r1: `key_bits` = 192
    ///   * secp224r1: `key_bits` = 224
    ///   * secp256r1: `key_bits` = 256
    ///   * secp384r1: `key_bits` = 384
    ///   * secp521r1: `key_bits` = 512
    SecpR1,
    /// SEC additional random curves over prime fields.
    /// This family comprises the following curves:
    ///   * secp160r2: `key_bits` = 160 (Deprecated)
    #[deprecated = "This family of curve is weak and deprecated."]
    SecpR2,
    /// SEC Koblitz curves over binary fields.
    /// This family comprises the following curves:
    ///   * sect163k1: `key_bits` = 163 (DEPRECATED)
    ///   * sect233k1: `key_bits` = 233
    ///   * sect239k1: `key_bits` = 239
    ///   * sect283k1: `key_bits` = 283
    ///   * sect409k1: `key_bits` = 409
    ///   * sect571k1: `key_bits` = 571
    SectK1,
    /// SEC random curves over binary fields.
    /// This family comprises the following curves:
    ///   * sect163r1: `key_bits` = 163 (DEPRECATED)
    ///   * sect233r1: `key_bits` = 233
    ///   * sect283r1: `key_bits` = 283
    ///   * sect409r1: `key_bits` = 409
    ///   * sect571r1: `key_bits` = 571
    SectR1,
    /// SEC additional random curves over binary fields.
    /// This family comprises the following curves:
    ///   * sect163r2 : key_bits = 163 (DEPRECATED)
    #[deprecated = "This family of curve is weak and deprecated."]
    SectR2,
    /// Brainpool P random curves.
    /// This family comprises the following curves:
    ///   * brainpoolP160r1: `key_bits` = 160 (DEPRECATED)
    ///   * brainpoolP192r1: `key_bits` = 192
    ///   * brainpoolP224r1: `key_bits` = 224
    ///   * brainpoolP256r1: `key_bits` = 256
    ///   * brainpoolP320r1: `key_bits` = 320
    ///   * brainpoolP384r1: `key_bits` = 384
    ///   * brainpoolP512r1: `key_bits` = 512
    BrainpoolPR1,
    /// Curve used primarily in France and elsewhere in Europe.
    /// This family comprises one 256-bit curve:
    ///   * FRP256v1: `key_bits` = 256
    Frp,
    /// Montgomery curves.
    /// This family comprises the following Montgomery curves:
    ///   * Curve25519: `key_bits` = 255
    ///   * Curve448: `key_bits` = 448
    Montgomery,
}

/// Enumeration of Diffie Hellman group families supported.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DhFamily {
    /// Diffie-Hellman groups defined in RFC 7919 Appendix A.
    /// This family includes groups with the following `key_bits`: 2048, 3072, 4096, 6144, 8192.
    /// An implementation can support all of these sizes or only a subset.
    Rfc7919,
}

/// Definition of the key policy, what is permitted to do with the key.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Usage flags for the key.
    pub key_usage_flags: UsageFlags,
    /// Permitted algorithms to be used with the key.
    pub key_algorithm: Algorithm,
}

/// Definition of the usage flags. They encode what kind of operations are permitted on the key.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UsageFlags {
    /// Permission to export the key.
    pub export: bool,
    /// Permission to copy the key.
    pub copy: bool,
    /// Permission for the implementation to cache the key.
    pub cache: bool,
    /// Permission to encrypt a message with the key.
    pub encrypt: bool,
    /// Permission to decrypt a message with the key.
    pub decrypt: bool,
    /// Permission to sign a message with the key.
    pub sign_message: bool,
    /// Permission to verify a message signature with the key.
    pub verify_message: bool,
    /// Permission to sign a message hash with the key.
    pub sign_hash: bool,
    /// Permission to verify a message hash with the key.
    pub verify_hash: bool,
    /// Permission to derive other keys from this key.
    pub derive: bool,
}

#[cfg(test)]
mod tests {
    use super::{KeyAttributes, KeyPolicy, KeyType, UsageFlags};
    use crate::operations::psa_algorithm::{
        Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricSignature, Cipher, FullLengthMac,
        Hash, Mac,
    };

    #[test]
    fn usage_flags() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let mut attributes = KeyAttributes {
            key_type: KeyType::RsaKeyPair,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };

        assert!(!attributes.is_exportable());
        assert!(!attributes.is_hash_signable());
        assert!(!attributes.is_hash_verifiable());
        attributes.key_policy.key_usage_flags.export = true;
        assert!(attributes.is_exportable());
        assert!(!attributes.is_hash_signable());
        assert!(!attributes.is_hash_verifiable());
        attributes.key_policy.key_usage_flags.sign_hash = true;
        assert!(attributes.is_exportable());
        assert!(attributes.is_hash_signable());
        assert!(!attributes.is_hash_verifiable());
        attributes.key_policy.key_usage_flags.verify_hash = true;
        assert!(attributes.is_exportable());
        assert!(attributes.is_hash_signable());
        assert!(attributes.is_hash_verifiable());
    }

    #[test]
    fn permits_good_alg() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let key_attributes = KeyAttributes {
            key_type: KeyType::Hmac,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };
        assert!(key_attributes.is_alg_permitted(alg));
    }

    #[test]
    fn permits_bad_alg() {
        let permitted_alg = Algorithm::Mac(Mac::FullLength(FullLengthMac::Hmac {
            hash_alg: Hash::Sha1,
        }));
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1,
        });
        let key_attributes = KeyAttributes {
            key_type: KeyType::Hmac,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };
        assert!(!key_attributes.is_alg_permitted(alg));
    }

    #[test]
    fn permits_wildcard_alg() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Any,
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha1,
        });
        let key_attributes = KeyAttributes {
            key_type: KeyType::Hmac,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };
        assert!(key_attributes.is_alg_permitted(alg));
    }

    #[test]
    fn permits_bad_wildcard_alg() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Any,
        });
        let key_attributes = KeyAttributes {
            key_type: KeyType::Hmac,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };
        assert!(!key_attributes.is_alg_permitted(alg));
    }

    #[test]
    fn compat_rsa() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let mut key_attributes = KeyAttributes {
            key_type: KeyType::RsaKeyPair,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };

        assert!(key_attributes.is_compatible_with_alg(alg));
        key_attributes.key_type = KeyType::RsaPublicKey;
        assert!(key_attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn compat_raw_data() {
        let permitted_alg = Algorithm::None;
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let key_attributes = KeyAttributes {
            key_type: KeyType::RawData,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };

        assert!(!key_attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn compat_block_cipher() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let mut alg = Algorithm::Cipher(Cipher::Ofb);
        let mut key_attributes = KeyAttributes {
            key_type: KeyType::Aes,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };

        assert!(key_attributes.is_compatible_with_alg(alg));
        key_attributes.key_type = KeyType::Des;
        assert!(key_attributes.is_compatible_with_alg(alg));
        key_attributes.key_type = KeyType::Camellia;
        assert!(key_attributes.is_compatible_with_alg(alg));
        alg = Algorithm::Aead(Aead::AeadWithDefaultLengthTag(
            AeadWithDefaultLengthTag::Ccm,
        ));
        assert!(key_attributes.is_compatible_with_alg(alg));
        key_attributes.key_type = KeyType::Des;
        assert!(!key_attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn compat_chacha() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let alg = Algorithm::Aead(Aead::AeadWithDefaultLengthTag(
            AeadWithDefaultLengthTag::Chacha20Poly1305,
        ));
        let key_attributes = KeyAttributes {
            key_type: KeyType::Chacha20,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };

        assert!(key_attributes.is_compatible_with_alg(alg));
    }

    #[test]
    fn bad_compat() {
        let permitted_alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let alg = Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
        let key_attributes = KeyAttributes {
            key_type: KeyType::Hmac,
            key_bits: 1024,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                key_algorithm: permitted_alg,
            },
        };

        assert!(!key_attributes.is_compatible_with_alg(alg));
    }
}
