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

use crate::operations::psa_algorithm::Algorithm;

/// Native definition of the attributes needed to fully describe
/// a cryptographic key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeyAttributes {
    /// Intrinsic category and type of a key
    pub key_type: KeyType,
    /// Size of a key in bits
    pub key_bits: u32,
    /// Policy restricting the permitted usage of the key
    pub key_policy: KeyPolicy,
}

/// Enumeration of key types supported.
#[derive(Copy, Clone, Debug, PartialEq)]
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

/// Enumeration of elliptic curve families supported. They are needed to create an ECC key.
/// The specific curve used for each family is given by the `key_bits` field of the key attributes.
/// See the book for more details.
#[derive(Copy, Clone, Debug, PartialEq)]
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
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DhFamily {
    /// Diffie-Hellman groups defined in RFC 7919 Appendix A.
    /// This family includes groups with the following `key_bits`: 2048, 3072, 4096, 6144, 8192.
    /// An implementation can support all of these sizes or only a subset.
    Rfc7919,
}

/// Definition of the key policy, what is permitted to do with the key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeyPolicy {
    /// Usage flags for the key.
    pub key_usage_flags: UsageFlags,
    /// Permitted algorithms to be used with the key.
    pub key_algorithm: Algorithm,
}

/// Definition of the usage flags. They encode what kind of operations are permitted on the key.
#[derive(Copy, Clone, Debug, PartialEq)]
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
