// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaVerifyMessage operation
//!
//! Verify the signature of a message using a public key.
use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::AsymmetricSignature;

/// Native object for asymmetric verification of signatures.
#[derive(Debug)]
pub struct Operation {
    /// `key_name` specifies the key to be used for verification.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The `message` whose signature is to be verified for the
    /// asymmetric signing operation.
    pub message: zeroize::Zeroizing<Vec<u8>>,
    /// Buffer containing the signature to verify.
    pub signature: zeroize::Zeroizing<Vec<u8>>,
}

/// Native object for asymmetric verification of signatures.
///
/// The true result of the operation is sent as a `status` code in the response.
#[derive(Copy, Clone, Debug)]
pub struct Result;

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows verifying signatures on messages
    /// * the key policy allows the verification algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_verify_message()?;
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
        let mut usage_flags = UsageFlags::default();
        let _ = usage_flags.set_verify_hash();
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags,
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
            signature: vec![0xa5; 65].into(),
        })
        .validate(get_attrs())
        .unwrap();
    }

    #[test]
    fn cannot_sign() {
        let mut attrs = get_attrs();
        attrs.policy.usage_flags = UsageFlags::default();
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                message: vec![0xff; 32].into(),
                signature: vec![0xa5; 65].into(),
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
                signature: vec![0xa5; 65].into(),
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
                signature: vec![0xa5; 65].into(),
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }
}
