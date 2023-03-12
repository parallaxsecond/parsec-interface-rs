// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaAsymmetricEncrypt operation
//!
//! Encrypt a short message with a public key.

use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::AsymmetricEncryption;
use crate::requests::ResponseStatus;
use derivative::Derivative;

/// Native object for asymmetric encryption operations.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// Defines which key should be used for the encryption operation.
    pub key_name: String,
    /// An asymmetric encryption algorithm that is compatible with the key type
    pub alg: AsymmetricEncryption,
    /// The short message to be encrypted.
    #[derivative(Debug = "ignore")]
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
    /// Salt to use during encryption, if supported by the algorithm.
    #[derivative(Debug = "ignore")]
    pub salt: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows encrypting messages
    /// * the key policy allows the encryption algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    /// * if the algorithm is RsaPkcs1v15Crypt, it has no salt (it is not compatible with salt)
    /// * the message to encrypt is valid (not length 0)
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_encrypt_message()?;
        key_attributes.permits_alg(self.alg.into())?;
        key_attributes.compatible_with_alg(self.alg.into())?;
        if (self.alg == AsymmetricEncryption::RsaPkcs1v15Crypt && self.salt.is_some())
            || self.plaintext.is_empty()
        {
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }
        Ok(())
    }
}

/// Native object for asymmetric encrypt result.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// The `ciphertext` field contains the encrypted short message.
    #[derivative(Debug = "ignore")]
    pub ciphertext: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::psa_algorithm::{AsymmetricEncryption, Hash};
    use crate::operations::psa_key_attributes::{Lifetime, Policy, Type, UsageFlags};

    fn get_attrs() -> Attributes {
        let mut usage_flags = UsageFlags::default();
        let _ = usage_flags.set_encrypt();
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::RsaKeyPair,
            bits: 256,
            policy: Policy {
                usage_flags,
                permitted_algorithms: AsymmetricEncryption::RsaPkcs1v15Crypt.into(),
            },
        }
    }

    #[test]
    fn validate_success() {
        (Operation {
            key_name: String::from("some key"),
            alg: AsymmetricEncryption::RsaPkcs1v15Crypt,
            plaintext: vec![0xff, 32].into(),
            salt: None,
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
                alg: AsymmetricEncryption::RsaPkcs1v15Crypt,
                plaintext: vec![0xff, 32].into(),
                salt: None,
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
                alg: AsymmetricEncryption::RsaOaep {
                    hash_alg: Hash::Sha256,
                },
                plaintext: vec![0xff, 32].into(),
                salt: None,
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
                alg: AsymmetricEncryption::RsaPkcs1v15Crypt,
                plaintext: vec![].into(),
                salt: None,
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorInvalidArgument
        );
    }

    #[test]
    fn salt_with_rsapkcs1v15crypt() {
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AsymmetricEncryption::RsaPkcs1v15Crypt,
                plaintext: vec![0xff, 32].into(),
                salt: Some(zeroize::Zeroizing::new(vec![0xff, 32])),
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorInvalidArgument
        );
    }
}
