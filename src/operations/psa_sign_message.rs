// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaSignMessage operation
//!
//! Sign a message with a private key.

use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::AsymmetricSignature;

/// Native object for asymmetric sign operations.
#[derive(Debug)]
pub struct Operation {
    /// Defines which key should be used for the signing operation.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The input whose signature is to be verified. This is usually the hash of a message.
    pub message: zeroize::Zeroizing<Vec<u8>>,
}

/// Native object for asymmetric sign result.
#[derive(Debug)]
pub struct Result {
    /// The `signature` field contains the resulting bytes from the signing operation. The format of
    /// the signature is as specified by the provider doing the signing.
    pub signature: zeroize::Zeroizing<Vec<u8>>,
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows signing messages
    /// * the key policy allows the signing algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_sign_message()?;
        key_attributes.permits_alg(self.alg.into())?;
        key_attributes.compatible_with_alg(self.alg.into())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
    use crate::operations::psa_key_attributes::{EccFamily, Lifetime, Policy, Type, UsageFlags};
    use crate::requests::ResponseStatus;

    fn get_attrs() -> Attributes {
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: true,
                    verify_message: false,
                    sign_hash: true,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                }),
            },
        }
    }

    #[test]
    fn validate_success() {
        (Operation {
            key_name: String::from("some key"),
            alg: AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            },
            message: vec![0xff; 32].into(),
        })
        .validate(get_attrs())
        .unwrap();
    }

    #[test]
    fn cannot_sign() {
        let mut attrs = get_attrs();
        attrs.policy.usage_flags.sign_hash = false;
        attrs.policy.usage_flags.sign_message = false;
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                message: vec![0xff; 32].into(),
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
                    hash_alg: Hash::Sha224.into(),
                },
                message: vec![0xff; 28].into(),
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
                    hash_alg: Hash::Sha224.into(),
                },
                message: vec![0xff; 28].into(),
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }
}
