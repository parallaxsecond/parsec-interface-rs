// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

pub mod psa_sign_hash;
pub mod psa_verify_hash;
pub mod psa_sign_message;
pub mod psa_verify_message;
pub mod psa_asymmetric_encrypt;
pub mod psa_asymmetric_decrypt;
pub mod psa_aead_encrypt;
pub mod psa_aead_decrypt;
pub mod psa_generate_key;
pub mod psa_destroy_key;
pub mod psa_export_public_key;
pub mod psa_export_key;
pub mod psa_import_key;
pub mod list_opcodes;
pub mod list_providers;
pub mod list_authenticators;
pub mod list_keys;
pub mod list_clients;
pub mod delete_client;
pub mod ping;
pub mod psa_key_attributes;
pub mod psa_algorithm;
pub mod psa_generate_random;
pub mod psa_hash_compute;
pub mod psa_hash_compare;
pub mod psa_raw_key_agreement;
pub mod can_do_crypto;

use zeroize::Zeroize;

use crate::requests::{ResponseStatus, Result};
use log::error;
use psa_algorithm::algorithm::{aead::AeadWithDefaultLengthTag, key_agreement::Raw, Cipher, Hash};
use psa_key_attributes::key_type::{DhFamily, EccFamily};
use can_do_crypto::CheckType;
use std::convert::TryFrom;

impl TryFrom<i32> for Cipher {
    type Error = ResponseStatus;
    fn try_from(cipher_val: i32) -> Result<Self> {
        Cipher::from_i32(cipher_val).ok_or_else(|| {
            error!(
                "Value {} not supported as a cipher algorithm encoding.",
                cipher_val
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

impl TryFrom<i32> for Hash {
    type Error = ResponseStatus;
    fn try_from(hash_val: i32) -> Result<Self> {
        Hash::from_i32(hash_val).ok_or_else(|| {
            error!(
                "Value {} not supported as a hash algorithm encoding.",
                hash_val
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

impl TryFrom<i32> for AeadWithDefaultLengthTag {
    type Error = ResponseStatus;
    fn try_from(aead_val: i32) -> Result<Self> {
        AeadWithDefaultLengthTag::from_i32(aead_val).ok_or_else(|| {
            error!(
                "Value {} not supported as an AEAD with default tag length algorithm encoding.",
                aead_val
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

impl TryFrom<i32> for Raw {
    type Error = ResponseStatus;
    fn try_from(key_agreement_val: i32) -> Result<Self> {
        Raw::from_i32(key_agreement_val).ok_or_else(|| {
            error!(
                "Value {} not supported as a raw key agreement algorithm encoding.",
                key_agreement_val
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

impl TryFrom<i32> for EccFamily {
    type Error = ResponseStatus;
    fn try_from(ecc_family_val: i32) -> Result<Self> {
        EccFamily::from_i32(ecc_family_val).ok_or_else(|| {
            error!(
                "Value {} not supported as an ECC family encoding.",
                ecc_family_val
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

impl TryFrom<i32> for DhFamily {
    type Error = ResponseStatus;
    fn try_from(dh_family_val: i32) -> Result<Self> {
        DhFamily::from_i32(dh_family_val).ok_or_else(|| {
            error!(
                "Value {} not supported as a DH family encoding.",
                dh_family_val
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

impl TryFrom<i32> for CheckType {
    type Error = ResponseStatus;
    fn try_from(check_type_val: i32) -> Result<Self> {
        CheckType::from_i32(check_type_val).ok_or_else(|| {
            error!(
                "Value {} not supported as a check type.",
                check_type_val
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

pub(super) trait ClearProtoMessage {
    fn clear_message(&mut self) {}
}

// Implement a no-op zeroize for types that don't contain sensitive data
macro_rules! empty_clear_message {
    ($type:ty) => {
        impl ClearProtoMessage for $type {
            fn clear_message(&mut self) {}
        }
    };
}

empty_clear_message!(list_opcodes::Operation);
empty_clear_message!(list_opcodes::Result);
empty_clear_message!(list_providers::Operation);
empty_clear_message!(list_providers::Result);
empty_clear_message!(list_authenticators::Operation);
empty_clear_message!(list_authenticators::Result);
empty_clear_message!(list_keys::Operation);
empty_clear_message!(list_keys::Result);
empty_clear_message!(list_clients::Operation);
empty_clear_message!(list_clients::Result);
empty_clear_message!(delete_client::Operation);
empty_clear_message!(delete_client::Result);
empty_clear_message!(ping::Operation);
empty_clear_message!(ping::Result);
empty_clear_message!(psa_destroy_key::Operation);
empty_clear_message!(psa_destroy_key::Result);
empty_clear_message!(psa_generate_key::Operation);
empty_clear_message!(psa_generate_key::Result);
empty_clear_message!(psa_export_public_key::Operation);
empty_clear_message!(psa_export_key::Operation);
empty_clear_message!(psa_import_key::Result);
empty_clear_message!(psa_verify_hash::Result);
empty_clear_message!(psa_verify_message::Result);
empty_clear_message!(psa_generate_random::Operation);
empty_clear_message!(psa_hash_compare::Result);
empty_clear_message!(can_do_crypto::Operation);
empty_clear_message!(can_do_crypto::Result);

impl ClearProtoMessage for psa_sign_hash::Operation {
    fn clear_message(&mut self) {
        self.hash.zeroize();
    }
}

impl ClearProtoMessage for psa_sign_hash::Result {
    fn clear_message(&mut self) {
        self.signature.zeroize();
    }
}

impl ClearProtoMessage for psa_verify_hash::Operation {
    fn clear_message(&mut self) {
        self.hash.zeroize();
        self.signature.zeroize();
    }
}

impl ClearProtoMessage for psa_sign_message::Operation {
    fn clear_message(&mut self) {
        self.message.zeroize();
    }
}

impl ClearProtoMessage for psa_sign_message::Result {
    fn clear_message(&mut self) {
        self.signature.zeroize();
    }
}

impl ClearProtoMessage for psa_verify_message::Operation {
    fn clear_message(&mut self) {
        self.message.zeroize();
        self.signature.zeroize();
    }
}

impl ClearProtoMessage for psa_import_key::Operation {
    fn clear_message(&mut self) {
        self.data.zeroize();
    }
}

impl ClearProtoMessage for psa_export_public_key::Result {
    fn clear_message(&mut self) {
        self.data.zeroize();
    }
}

impl ClearProtoMessage for psa_export_key::Result {
    fn clear_message(&mut self) {
        self.data.zeroize();
    }
}

impl ClearProtoMessage for psa_asymmetric_encrypt::Operation {
    fn clear_message(&mut self) {
        self.plaintext.zeroize();
        self.salt.zeroize();
    }
}

impl ClearProtoMessage for psa_asymmetric_decrypt::Operation {
    fn clear_message(&mut self) {
        self.salt.zeroize();
        self.ciphertext.zeroize();
    }
}

impl ClearProtoMessage for psa_asymmetric_encrypt::Result {
    fn clear_message(&mut self) { self.ciphertext.zeroize(); }
}

impl ClearProtoMessage for psa_asymmetric_decrypt::Result {
    fn clear_message(&mut self) { self.plaintext.zeroize(); }
}

impl ClearProtoMessage for psa_aead_encrypt::Operation {
    fn clear_message(&mut self) {
        self.plaintext.zeroize();
        self.additional_data.zeroize();
        self.nonce.zeroize();
    }
}

impl ClearProtoMessage for psa_aead_decrypt::Operation {
    fn clear_message(&mut self) {
        self.additional_data.zeroize();
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

impl ClearProtoMessage for psa_aead_encrypt::Result {
    fn clear_message(&mut self) { self.ciphertext.zeroize(); }
}

impl ClearProtoMessage for psa_aead_decrypt::Result {
    fn clear_message(&mut self) {
        self.plaintext.zeroize()
    }
}

impl ClearProtoMessage for psa_generate_random::Result {
    fn clear_message(&mut self) { self.random_bytes.zeroize(); }
}

impl ClearProtoMessage for psa_hash_compute::Operation {
    fn clear_message(&mut self) { self.input.zeroize(); }
}

impl ClearProtoMessage for psa_hash_compute::Result {
    fn clear_message(&mut self) { self.hash.zeroize(); }
}

impl ClearProtoMessage for psa_hash_compare::Operation {
    fn clear_message(&mut self) {
        self.input.zeroize();
        self.hash.zeroize();
    }
}

impl ClearProtoMessage for psa_raw_key_agreement::Operation {
    fn clear_message(&mut self) {
        self.peer_key.zeroize();
    }
}

impl ClearProtoMessage for psa_raw_key_agreement::Result {
    fn clear_message(&mut self) {
        self.shared_secret.zeroize();
    }
}

#[test]
fn i32_conversions() {
    assert_eq!(Cipher::try_from(56).unwrap_err(), ResponseStatus::InvalidEncoding);
    assert_eq!(Cipher::try_from(-5).unwrap_err(), ResponseStatus::InvalidEncoding);
    assert_eq!(Hash::try_from(89).unwrap_err(), ResponseStatus::InvalidEncoding);
    assert_eq!(Hash::try_from(-4).unwrap_err(), ResponseStatus::InvalidEncoding);
    assert_eq!(EccFamily::try_from(78).unwrap_err(), ResponseStatus::InvalidEncoding);

}
