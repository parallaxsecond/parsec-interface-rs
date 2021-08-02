// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaAeadEncrypt operation
//!
//! Process an authenticated encryption operation.

use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::Aead;
use crate::requests::ResponseStatus;
use derivative::Derivative;

/// Native object for AEAD encryption operations.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// Defines which key should be used for the encryption operation.
    pub key_name: String,
    /// An AEAD encryption algorithm that is compatible with the key type.
    pub alg: Aead,
    /// Nonce or IV to use.
    #[derivative(Debug = "ignore")]
    pub nonce: zeroize::Zeroizing<Vec<u8>>,
    /// Additional data that will be authenticated but not encrypted.
    #[derivative(Debug = "ignore")]
    pub additional_data: zeroize::Zeroizing<Vec<u8>>,
    /// Data that will be authenticated and encrypted.
    #[derivative(Debug = "ignore")]
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows encrypting messages
    /// * the key policy allows the encryption algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    /// * the message to encrypt is valid (not length 0)
    /// * the nonce is valid (not length 0)
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_encrypt_message()?;
        key_attributes.permits_alg(self.alg.into())?;
        key_attributes.compatible_with_alg(self.alg.into())?;
        if self.plaintext.is_empty() || self.nonce.is_empty() {
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }
        Ok(())
    }
}

/// Native object for AEAD encrypt result.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// The `ciphertext` field contains the encrypted and authenticated data.For algorithms where
    /// the encrypted data and the authentication tag are defined as separate outputs, the authentication
    /// tag is appended to the encrypted data.
    #[derivative(Debug = "ignore")]
    pub ciphertext: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::psa_algorithm::AeadWithDefaultLengthTag;
    use crate::operations::psa_key_attributes::{Lifetime, Policy, Type, UsageFlags};
    use psa_crypto::types::algorithm::Aead;

    fn get_attrs() -> Attributes {
        let mut usage_flags = UsageFlags::default();
        let _ = usage_flags.set_encrypt();
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::Aes,
            bits: 0,
            policy: Policy {
                usage_flags,
                permitted_algorithms: Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm)
                    .into(),
            },
        }
    }

    #[test]
    fn validate_success() {
        (Operation {
            key_name: String::from("some key"),
            alg: AeadWithDefaultLengthTag::Ccm.into(),
            plaintext: vec![0xff, 32].into(),
            nonce: vec![0xaa, 12].into(),
            additional_data: vec![0xff, 16].into(),
        })
        .validate(get_attrs())
        .unwrap();
    }

    #[test]
    fn cannot_encrypt() {
        let mut attrs = get_attrs();
        attrs.policy.usage_flags = UsageFlags::default();
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AeadWithDefaultLengthTag::Ccm.into(),
                plaintext: vec![0xff, 32].into(),
                nonce: vec![0xaa, 12].into(),
                additional_data: vec![0xff, 16].into()
            })
            .validate(attrs)
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }

    #[test]
    fn wrong_algorithm() {
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AeadWithDefaultLengthTag::Gcm.into(),
                plaintext: vec![0xff, 32].into(),
                nonce: vec![0xaa, 12].into(),
                additional_data: vec![0xff, 16].into()
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }

    #[test]
    fn invalid_plaintext() {
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AeadWithDefaultLengthTag::Ccm.into(),
                plaintext: vec![].into(),
                nonce: vec![0xaa, 12].into(),
                additional_data: vec![0xff, 16].into()
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorInvalidArgument
        );
    }

    #[test]
    fn invalid_nonce() {
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AeadWithDefaultLengthTag::Ccm.into(),
                plaintext: vec![0xff, 32].into(),
                nonce: vec![].into(),
                additional_data: vec![0xff, 16].into()
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorInvalidArgument
        );
    }
}
