// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaVerifyHash operation
//!
//! Verify the signature of a hash or short message using a public key.
use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::AsymmetricSignature;
use crate::requests::ResponseStatus;

/// Native object for asymmetric verification of signatures.
#[derive(Debug)]
pub struct Operation {
    /// `key_name` specifies the key to be used for verification.
    pub key_name: String,
    /// An asymmetric signature algorithm that separates the hash and sign operations, that is
    /// compatible with the type of key.
    pub alg: AsymmetricSignature,
    /// The `hash` contains a short message or hash value as described for the
    /// asymmetric signing operation.
    pub hash: Vec<u8>,
    /// Buffer containing the signature to verify.
    pub signature: Vec<u8>,
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
    /// * the key policy allows verifying signatures on hashes
    /// * the key policy allows the verification algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    /// * the length of the given digest is consistent with the specified verification algorithm
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_verify_hash()?;
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
    use crate::operations::psa_key_attributes::{EccFamily, Lifetime, Policy, Type, UsageFlags};

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
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: true,
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
            hash: vec![0xff; 32],
            signature: vec![0xa5; 65],
        })
        .validate(get_attrs())
        .unwrap();
    }

    #[test]
    fn cannot_sign() {
        let mut attrs = get_attrs();
        attrs.policy.usage_flags.verify_hash = false;
        assert_eq!(
            (Operation {
                key_name: String::from("some key"),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: vec![0xff; 32],
                signature: vec![0xa5; 65],
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
                hash: vec![0xff; 28],
                signature: vec![0xa5; 65],
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
                hash: vec![0xff; 28],
                signature: vec![0xa5; 65],
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
                    hash_alg: Hash::Sha256.into(),
                },
                hash: vec![0xff; 16],
                signature: vec![0xa5; 65],
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorInvalidArgument
        );
    }
}
