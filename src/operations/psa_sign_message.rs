// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PsaSignMessage operation
//! 
//! //! Sign an hash generated from message with a private key.

use super::psa_key_attributes::Attributes;
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
