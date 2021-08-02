// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaRawKeyAgreement operation
//!
//! Perform a raw key agreement.

use super::psa_key_attributes::Attributes;
use crate::operations::psa_algorithm::{KeyAgreement, RawKeyAgreement};
use derivative::Derivative;

/// Native object for raw key agreement operation.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Operation {
    /// `alg` specifies the raw key agreement algorithm to use. It must allow the `derive` usage flag.
    pub alg: RawKeyAgreement,
    /// `private_key_name` specifies a name of the private key to use in the key agreement operation.
    pub private_key_name: String,
    /// `peer_key` contains the bytes of a peers public key, to be used in the key agreement operation.
    /// This must be in the format that `PsaImportKey` accepts.
    #[derivative(Debug = "ignore")]
    pub peer_key: zeroize::Zeroizing<Vec<u8>>,
}

/// Native object for result for raw key agreement operation.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Result {
    /// `data` holds the bytes defining the key, formatted as specified
    /// by the provider for which the request was made.
    #[derivative(Debug = "ignore")]
    pub shared_secret: crate::secrecy::Secret<Vec<u8>>,
}

impl Operation {
    /// Validate the contents of the operation against the attributes of the key it targets
    ///
    /// This method checks that:
    /// * the key policy allows derivation
    /// * the key policy allows the key agreement algorithm requested in the operation
    /// * the key type is compatible with the requested algorithm
    pub fn validate(&self, key_attributes: Attributes) -> crate::requests::Result<()> {
        key_attributes.can_derive_from()?;
        key_attributes.permits_alg(KeyAgreement::Raw(self.alg).into())?;
        key_attributes.compatible_with_alg(KeyAgreement::Raw(self.alg).into())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::psa_algorithm::{KeyAgreement, RawKeyAgreement};
    use crate::operations::psa_key_attributes::{EccFamily, Lifetime, Policy, Type, UsageFlags};
    use crate::requests::ResponseStatus;

    fn get_attrs() -> Attributes {
        let mut usage_flags = UsageFlags::default();
        let _ = usage_flags.set_derive();
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags,
                permitted_algorithms: KeyAgreement::Raw(RawKeyAgreement::Ecdh).into(),
            },
        }
    }

    #[test]
    fn validate_success() {
        (Operation {
            private_key_name: String::from("some key"),
            alg: RawKeyAgreement::Ecdh,
            peer_key: vec![0xff, 32].into(),
        })
        .validate(get_attrs())
        .unwrap();
    }

    #[test]
    fn cannot_derive() {
        let mut attrs = get_attrs();
        attrs.policy.usage_flags = UsageFlags::default();
        assert_eq!(
            (Operation {
                private_key_name: String::from("some key"),
                alg: RawKeyAgreement::Ecdh,
                peer_key: vec![0xff, 32].into(),
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
                private_key_name: String::from("some key"),
                alg: RawKeyAgreement::Ffdh,
                peer_key: vec![0xff, 32].into(),
            })
            .validate(get_attrs())
            .unwrap_err(),
            ResponseStatus::PsaErrorNotPermitted
        );
    }
}
