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
//! Key attributes module

use crate::operations::algorithm::Algorithm;

/// Native definition of the attributes needed to fully describe
/// a cryptographic key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeyAttributes {
    pub key_type: KeyType,
    pub key_bits: u32,
    pub key_policy: KeyPolicy,
}

/// Enumeration of key types supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyType {
    RawData,
    Hmac,
    Derive,
    Aes,
    Des,
    Camellia,
    Arc4,
    Chacha20,
    RsaPublicKey,
    RsaKeyPair,
    EccKeyPair { curve_family: EccFamily },
    EccPublicKey { curve_family: EccFamily },
    DhKeyPair { group_family: DhFamily },
    DhPublicKey { group_family: DhFamily },
}

/// Enumeration of elliptic curve families supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EccFamily {
    SecpK1,
    SecpR1,
    SecpR2,
    SectK1,
    SectR1,
    SectR2,
    BrainpoolPR1,
    Frp,
    Montgomery,
}

/// Enumeration of Diffie Hellman group families supported.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DhFamily {
    Rfc7919,
}

/// Definition of the key policy, what is permitted to do with the key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeyPolicy {
    pub key_usage_flags: UsageFlags,
    pub key_algorithm: Algorithm,
}

/// Definition of the usage flags.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct UsageFlags {
    pub export: bool,
    pub copy: bool,
    pub cache: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub sign_message: bool,
    pub verify_message: bool,
    pub sign_hash: bool,
    pub verify_hash: bool,
    pub derive: bool,
}
