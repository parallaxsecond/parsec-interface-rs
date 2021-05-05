// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// Include the Rust generated file in its own module.
use zeroize::Zeroize;

macro_rules! include_protobuf_as_module {
    ($name:ident) => {
        pub mod $name {
            #[allow(unused)]
            #[macro_export]
            use zeroize::Zeroize;
            // The generated Rust file is in OUT_DIR, named $name.rs
            include!(concat!(env!("OUT_DIR"), "/", stringify!($name), ".rs"));
        }
    };
}

include_protobuf_as_module!(psa_sign_hash);
include_protobuf_as_module!(psa_verify_hash);
include_protobuf_as_module!(psa_sign_message);
include_protobuf_as_module!(psa_verify_message);
include_protobuf_as_module!(psa_asymmetric_encrypt);
include_protobuf_as_module!(psa_asymmetric_decrypt);
include_protobuf_as_module!(psa_aead_encrypt);
include_protobuf_as_module!(psa_aead_decrypt);
include_protobuf_as_module!(psa_generate_key);
include_protobuf_as_module!(psa_destroy_key);
include_protobuf_as_module!(psa_export_public_key);
include_protobuf_as_module!(psa_export_key);
include_protobuf_as_module!(psa_import_key);
include_protobuf_as_module!(list_opcodes);
include_protobuf_as_module!(list_providers);
include_protobuf_as_module!(list_authenticators);
include_protobuf_as_module!(list_keys);
include_protobuf_as_module!(list_clients);
include_protobuf_as_module!(delete_client);
include_protobuf_as_module!(ping);
include_protobuf_as_module!(psa_key_attributes);
include_protobuf_as_module!(psa_algorithm);
include_protobuf_as_module!(psa_generate_random);
include_protobuf_as_module!(psa_hash_compute);
include_protobuf_as_module!(psa_hash_compare);
include_protobuf_as_module!(psa_raw_key_agreement);

use crate::requests::{ResponseStatus, Result};
use log::error;
use psa_algorithm::algorithm::{aead::AeadWithDefaultLengthTag, key_agreement::Raw, Cipher, Hash};
use psa_key_attributes::key_type::{DhFamily, EccFamily};
use std::convert::TryFrom;

impl TryFrom<i32> for Cipher {
    type Error = ResponseStatus;
    fn try_from(cipher_val: i32) -> Result<Self> {
        Cipher::from_i32(cipher_val).ok_or_else(|| {
            error!(
                "Value {} not recognised as a valid cipher algorithm encoding.",
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
                "Value {} not recognised as a valid hash algorithm encoding.",
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
                "Value {} not recognised as a valid AEAD with default tag length algorithm encoding.",
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
                "Value {} not recognised as a valid raw key agreement algorithm encoding.",
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
                "Value {} not recognised as a valid ECC family encoding.",
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
                "Value {} not recognised as a valid DH family encoding.",
                dh_family_val
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
