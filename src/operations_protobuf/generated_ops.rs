// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// Include the Rust generated file in its own module.
macro_rules! include_protobuf_as_module {
    ($name:ident) => {
        pub mod $name {
            // The generated Rust file is in OUT_DIR, named $name.rs
            include!(concat!(env!("OUT_DIR"), "/", stringify!($name), ".rs"));
        }
    };
}

include_protobuf_as_module!(psa_sign_hash);
include_protobuf_as_module!(psa_verify_hash);
include_protobuf_as_module!(psa_generate_key);
include_protobuf_as_module!(psa_destroy_key);
include_protobuf_as_module!(psa_export_public_key);
include_protobuf_as_module!(psa_import_key);
include_protobuf_as_module!(list_opcodes);
include_protobuf_as_module!(list_providers);
include_protobuf_as_module!(ping);
include_protobuf_as_module!(psa_key_attributes);
include_protobuf_as_module!(psa_algorithm);

use crate::requests::{ResponseStatus, Result};
use log::error;
use psa_algorithm::algorithm::{aead::AeadWithDefaultLengthTag, key_agreement::Raw, Cipher, Hash};
use psa_key_attributes::key_type::{DhFamily, EccFamily};
use std::convert::TryFrom;

impl TryFrom<i32> for Cipher {
    type Error = ResponseStatus;
    fn try_from(cipher_val: i32) -> Result<Self> {
        Ok(Cipher::from_i32(cipher_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid cipher algorithm encoding.",
                cipher_val
            );
            ResponseStatus::InvalidEncoding
        })?)
    }
}

impl TryFrom<i32> for Hash {
    type Error = ResponseStatus;
    fn try_from(hash_val: i32) -> Result<Self> {
        Ok(Hash::from_i32(hash_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid hash algorithm encoding.",
                hash_val
            );
            ResponseStatus::InvalidEncoding
        })?)
    }
}

impl TryFrom<i32> for AeadWithDefaultLengthTag {
    type Error = ResponseStatus;
    fn try_from(aead_val: i32) -> Result<Self> {
        Ok(AeadWithDefaultLengthTag::from_i32(aead_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid AEAD with default tag length algorithm encoding.",
                aead_val
            );
            ResponseStatus::InvalidEncoding
        })?)
    }
}

impl TryFrom<i32> for Raw {
    type Error = ResponseStatus;
    fn try_from(key_agreement_val: i32) -> Result<Self> {
        Ok(Raw::from_i32(key_agreement_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid raw key agreement algorithm encoding.",
                key_agreement_val
            );
            ResponseStatus::InvalidEncoding
        })?)
    }
}

impl TryFrom<i32> for EccFamily {
    type Error = ResponseStatus;
    fn try_from(ecc_family_val: i32) -> Result<Self> {
        Ok(EccFamily::from_i32(ecc_family_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid ECC family encoding.",
                ecc_family_val
            );
            ResponseStatus::InvalidEncoding
        })?)
    }
}

impl TryFrom<i32> for DhFamily {
    type Error = ResponseStatus;
    fn try_from(dh_family_val: i32) -> Result<Self> {
        Ok(DhFamily::from_i32(dh_family_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid DH family encoding.",
                dh_family_val
            );
            ResponseStatus::InvalidEncoding
        })?)
    }
}
