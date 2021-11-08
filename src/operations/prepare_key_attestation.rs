// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # PrepareKeyAttestation operation
//!
//! Produce any parameters required for the AttestKey operation
use derivative::Derivative;
use zeroize::Zeroizing;

/// Native operation for retrieving key attestation parameters
#[derive(Debug)]
#[non_exhaustive]
pub enum Operation {
    /// Get parameters for TPM 2.0 ActivateCredential operation
    ActivateCredential {
        /// Name of key to be attested
        attested_key_name: String,
        /// Name of key to be used for attesting
        attesting_key_name: Option<String>,
    },
}

/// Native result of retrieving key attestation parameters
#[derive(Derivative)]
#[derivative(Debug)]
#[non_exhaustive]
pub enum Result {
    /// Parameters for TPM 2.0 ActivateCredential operation
    ActivateCredential {
        /// TPM name of key to be attested
        #[derivative(Debug = "ignore")]
        name: Zeroizing<Vec<u8>>,
        /// TPM public key parameters of object to be attested
        #[derivative(Debug = "ignore")]
        public: Zeroizing<Vec<u8>>,
        /// Public part of attesting key
        #[derivative(Debug = "ignore")]
        attesting_key_pub: Zeroizing<Vec<u8>>,
    },
}
