// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaVerifyMessage operation
//!
//! Verify the signature of a hash or short message using a public key.
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
    /// The `hash` contains a short message or hash value as described for the
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
        key_attributes.can_verify_hash()?;
        key_attributes.permits_alg(self.alg.into())?;
        key_attributes.compatible_with_alg(self.alg.into())?;

        Ok(())
    }
}
