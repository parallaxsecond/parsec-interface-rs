// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaCipherDecrypt operation
//!
//! Decrypt a short message with a public key.

use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::Cipher;
use crate::requests::ResponseStatus;
use derivative::Derivative;

/// Native object for cipher decryption operations.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// Defines which key should be used for the signing operation.
    pub key_name: String,
    /// An cipher encryption algorithm to be used for decryption, that is compatible with the type of key.
    pub alg: Cipher,
    /// The short encrypted message to be decrypted.
    #[derivative(Debug = "ignore")]
    pub ciphertext: zeroize::Zeroizing<Vec<u8>>,
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows decrypting messages
    /// * the key policy allows the decryption algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    /// * the message to decrypt is valid (not length 0)
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_decrypt_message()?;
        key_attributes.permits_alg(self.alg.into())?;
        key_attributes.compatible_with_alg(self.alg.into())?;
        if self.ciphertext.is_empty() {
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }
        Ok(())
    }
}

/// Native object for cipher decrypt result.
// Debug derived as NativeResult enum requires it, even though nothing inside this Result is debuggable
// as `plaintext` is sensitive.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// Decrypted message
    #[derivative(Debug = "ignore")]
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::psa_algorithm::Cipher;
    use crate::operations::psa_key_attributes::{Lifetime, Policy, Type, UsageFlags};

    fn get_attrs() -> Attributes {
        let mut usage_flags = UsageFlags::default();
        let _ = usage_flags.set_decrypt();
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::Arc4,
            bits: 256,
            policy: Policy {
                usage_flags,
                permitted_algorithms: Cipher::StreamCipher.into(),
            },
        }
    }

    #[test]
    fn validate_success() {
        (Operation {
            key_name: String::from("some key"),
            alg: Cipher::StreamCipher,
            ciphertext: vec![0xff, 32].into(),
        })
        .validate(get_attrs())
        .unwrap();
    }

    #[test]
    fn cannot_decrypt() {
        let mut attrs = get_attrs();
        attrs.policy.usage_flags = UsageFlags::default();
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: Cipher::StreamCipher,
                ciphertext: vec![0xff, 32].into(),
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
                alg: Cipher::Cfb,
                ciphertext: vec![0xff, 32].into(),
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }

    #[test]
    fn invalid_ciphertext() {
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: Cipher::StreamCipher,
                ciphertext: vec![].into(),
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorInvalidArgument
        );
    }
}
