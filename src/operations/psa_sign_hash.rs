// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaSignHash operation
//!
//! Sign an already-calculated hash with a private key.

use super::psa_key_attributes::KeyAttributes;
use crate::operations::psa_algorithm::AsymmetricSignature;
use crate::requests::ResponseStatus;

/// Native object for asymmetric sign operations.
#[derive(Debug)]
pub struct Operation {
    /// Defines which key should be used for the signing operation.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The input whose signature is to be verified. This is usually the hash of a message.
    pub hash: Vec<u8>,
}

/// Native object for asymmetric sign result.
#[derive(Debug)]
pub struct Result {
    /// The `signature` field contains the resulting bytes from the signing operation. The format of
    /// the signature is as specified by the provider doing the signing.
    pub signature: Vec<u8>,
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows signing hashes
    /// * the key policy allows the signing algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    /// * the length of the given digest is consistent with the specified signing algorithm
    pub fn validate(&self, key_attributes: KeyAttributes) -> crate::requests::Result<()> {
        key_attributes.can_sign_hash()?;
        key_attributes.permits_alg(self.alg.into())?;
        key_attributes.compatible_with_alg(self.alg.into())?;
        if !self.alg.is_hash_len_permitted(self.hash.len()) {
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
    use crate::operations::psa_key_attributes::{EccFamily, KeyPolicy, KeyType, UsageFlags};

    fn get_attrs() -> KeyAttributes {
        KeyAttributes {
            key_type: KeyType::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            key_bits: 256,
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
                key_algorithm: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256,
                }),
            },
        }
    }

    #[test]
    fn validate_success() {
        (Operation {
            key_name: String::from("some key"),
            alg: AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256,
            },
            hash: vec![0xff; 32],
        })
        .validate(get_attrs())
        .unwrap();
    }

    #[test]
    fn cannot_sign() {
        let mut attrs = get_attrs();
        attrs.key_policy.key_usage_flags.sign_hash = false;
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256,
                },
                hash: vec![0xff; 32],
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
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha224,
                },
                hash: vec![0xff; 28],
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }

    #[test]
    fn wrong_scheme() {
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AsymmetricSignature::RsaPss {
                    hash_alg: Hash::Sha224,
                },
                hash: vec![0xff; 28],
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }

    #[test]
    fn invalid_hash() {
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256,
                },
                hash: vec![0xff; 16],
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorInvalidArgument
        );
    }
}
