// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//!
//! # Utilities for checking deprecated primatives
//! # by PSA Crypto API 1.0.0

use std::vec;

use psa_crypto::types::algorithm::*;

/// Check if any part of the algorithm is deprecated by PSA Crypto API
pub fn is_algorithm_deprecated(_alg: Algorithm) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    fn get_deprecated_hashes() -> Vec<Hash> {
        vec![Hash::Md2, Hash::Md4, Hash::Md5, Hash::Sha1]
    }

    fn get_selection_non_deprecated_hashes() -> Vec<Hash> {
        vec![Hash::Sha256, Hash::Sha3_512, Hash::Sha384, Hash::Ripemd160]
    }

    fn get_deprecated_macs() -> Vec<Mac> {
        let mut deprecated_macs: Vec<Mac> = vec![];
        for hash in get_deprecated_hashes() {
            deprecated_macs.push(Mac::FullLength(FullLengthMac::Hmac { hash_alg: hash }));
            // mac_length is chosen arbitary
            deprecated_macs.push(Mac::Truncated {
                mac_alg: FullLengthMac::Hmac { hash_alg: hash },
                mac_length: 1234,
            });
        }
        deprecated_macs
    }

    fn get_selection_non_deprecated_macs() -> Vec<Mac> {
        let mut selection_non_deprecated_macs: Vec<Mac> = vec![
            Mac::FullLength(FullLengthMac::CbcMac),
            Mac::FullLength(FullLengthMac::Cmac),
            Mac::Truncated {
                mac_alg: FullLengthMac::CbcMac,
                // mac_length is chosen arbitary
                mac_length: 1234,
            },
            Mac::Truncated {
                mac_alg: FullLengthMac::Cmac,
                // mac_length is chosen arbitary
                mac_length: 1234,
            },
        ];
        for hash in get_selection_non_deprecated_hashes() {
            selection_non_deprecated_macs
                .push(Mac::FullLength(FullLengthMac::Hmac { hash_alg: hash }));
            selection_non_deprecated_macs.push(Mac::Truncated {
                mac_alg: FullLengthMac::Hmac { hash_alg: hash },
                // mac_length is chosen arbitary
                mac_length: 1234,
            });
        }
        selection_non_deprecated_macs
    }

    fn get_deprecated_ciphers() -> Vec<Cipher> {
        vec![]
    }

    fn get_selection_non_deprecated_ciphers() -> Vec<Cipher> {
        vec![Cipher::Ctr, Cipher::CbcNoPadding, Cipher::StreamCipher]
    }

    fn get_deprecated_aeads() -> Vec<Aead> {
        vec![]
    }

    fn get_selection_non_deprecated_aeads() -> Vec<Aead> {
        vec![
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
            // tag_length is chosen arbitary
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Chacha20Poly1305,
                tag_length: 121,
            },
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                tag_length: 212,
            },
        ]
    }

    fn get_deprecated_asymmetric_signatures() -> Vec<AsymmetricSignature> {
        let mut deprecated_asymmetric_signatures = vec![];
        for hash in get_deprecated_hashes() {
            deprecated_asymmetric_signatures.push(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: hash.into(),
            });
            deprecated_asymmetric_signatures.push(AsymmetricSignature::RsaPss {
                hash_alg: hash.into(),
            });
            deprecated_asymmetric_signatures.push(AsymmetricSignature::Ecdsa {
                hash_alg: hash.into(),
            });
            deprecated_asymmetric_signatures.push(AsymmetricSignature::DeterministicEcdsa {
                hash_alg: hash.into(),
            });
        }
        deprecated_asymmetric_signatures
    }

    fn get_selection_non_deprecated_asymmetric_signatures() -> Vec<AsymmetricSignature> {
        let mut selection_non_deprecated_asymmetric_signatures = vec![
            AsymmetricSignature::RsaPkcs1v15SignRaw,
            AsymmetricSignature::EcdsaAny,
        ];
        for hash in get_selection_non_deprecated_hashes() {
            selection_non_deprecated_asymmetric_signatures.push(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: hash.into(),
                },
            );
            selection_non_deprecated_asymmetric_signatures.push(AsymmetricSignature::RsaPss {
                hash_alg: hash.into(),
            });
            selection_non_deprecated_asymmetric_signatures.push(AsymmetricSignature::Ecdsa {
                hash_alg: hash.into(),
            });
            selection_non_deprecated_asymmetric_signatures.push(
                AsymmetricSignature::DeterministicEcdsa {
                    hash_alg: hash.into(),
                },
            );
        }
        selection_non_deprecated_asymmetric_signatures
    }

    fn get_deprecated_asymmetric_encryptions() -> Vec<AsymmetricEncryption> {
        let mut deprecated_asymmetric_encryptions = vec![];
        for hash in get_deprecated_hashes() {
            deprecated_asymmetric_encryptions.push(AsymmetricEncryption::RsaOaep {
                hash_alg: hash.into(),
            });
        }
        deprecated_asymmetric_encryptions
    }

    fn get_selection_non_deprecated_asymmetric_encryptions() -> Vec<AsymmetricEncryption> {
        let mut selection_non_deprecated_asymmetric_encryptions =
            vec![AsymmetricEncryption::RsaPkcs1v15Crypt];
        for hash in get_selection_non_deprecated_hashes() {
            selection_non_deprecated_asymmetric_encryptions.push(AsymmetricEncryption::RsaOaep {
                hash_alg: hash.into(),
            });
        }
        selection_non_deprecated_asymmetric_encryptions
    }

    fn get_deprecated_key_derivations() -> Vec<KeyDerivation> {
        let mut deprecated_key_derivations = vec![];
        for hash in get_deprecated_hashes() {
            deprecated_key_derivations.push(KeyDerivation::Hkdf {
                hash_alg: hash.into(),
            });
            deprecated_key_derivations.push(KeyDerivation::Tls12Prf {
                hash_alg: hash.into(),
            });
            deprecated_key_derivations.push(KeyDerivation::Tls12PskToMs {
                hash_alg: hash.into(),
            });
        }
        deprecated_key_derivations
    }

    fn get_selection_non_deprecated_key_derivations() -> Vec<KeyDerivation> {
        let mut selection_non_deprecated_key_derivations = vec![];
        for hash in get_selection_non_deprecated_hashes() {
            selection_non_deprecated_key_derivations.push(KeyDerivation::Hkdf {
                hash_alg: hash.into(),
            });
            selection_non_deprecated_key_derivations.push(KeyDerivation::Tls12Prf {
                hash_alg: hash.into(),
            });
            selection_non_deprecated_key_derivations.push(KeyDerivation::Tls12PskToMs {
                hash_alg: hash.into(),
            });
        }
        selection_non_deprecated_key_derivations
    }

    fn get_deprecated_key_agreements() -> Vec<KeyAgreement> {
        let mut deprecated_key_agreements = vec![];
        for keyderv in get_deprecated_key_derivations() {
            deprecated_key_agreements.push(KeyAgreement::WithKeyDerivation {
                ka_alg: RawKeyAgreement::Ffdh,
                kdf_alg: keyderv,
            });
            deprecated_key_agreements.push(KeyAgreement::WithKeyDerivation {
                ka_alg: RawKeyAgreement::Ecdh,
                kdf_alg: keyderv,
            });
        }
        deprecated_key_agreements
    }

    fn get_selection_non_deprecated_key_agreements() -> Vec<KeyAgreement> {
        let mut selection_non_deprecated_key_agreements = vec![];
        for keyderv in get_selection_non_deprecated_key_derivations() {
            selection_non_deprecated_key_agreements.push(KeyAgreement::WithKeyDerivation {
                ka_alg: RawKeyAgreement::Ffdh,
                kdf_alg: keyderv,
            });
            selection_non_deprecated_key_agreements.push(KeyAgreement::WithKeyDerivation {
                ka_alg: RawKeyAgreement::Ecdh,
                kdf_alg: keyderv,
            });
        }
        selection_non_deprecated_key_agreements.push(KeyAgreement::Raw(RawKeyAgreement::Ffdh));
        selection_non_deprecated_key_agreements.push(KeyAgreement::Raw(RawKeyAgreement::Ecdh));
        selection_non_deprecated_key_agreements
    }

    fn get_deprecated_algorithms() -> Vec<Algorithm> {
        let mut deprecated_algorithms: Vec<Algorithm> = vec![];
        // Hashes
        for hash in get_deprecated_hashes() {
            deprecated_algorithms.push(Algorithm::Hash(hash));
        }

        // Macs
        for mac in get_deprecated_macs() {
            deprecated_algorithms.push(Algorithm::Mac(mac));
        }

        // Cipher
        for cipher in get_deprecated_ciphers() {
            deprecated_algorithms.push(Algorithm::Cipher(cipher));
        }
        // Aead
        for aead in get_deprecated_aeads() {
            deprecated_algorithms.push(Algorithm::Aead(aead));
        }

        // AsymmetricSignatures
        for asymm_sig in get_deprecated_asymmetric_signatures() {
            deprecated_algorithms.push(Algorithm::AsymmetricSignature(asymm_sig));
        }

        // AsymmetricEncryptions
        for asymm_enc in get_deprecated_asymmetric_encryptions() {
            deprecated_algorithms.push(Algorithm::AsymmetricEncryption(asymm_enc));
        }

        // KeyDerivations
        for key_derv in get_deprecated_key_derivations() {
            deprecated_algorithms.push(Algorithm::KeyDerivation(key_derv));
        }

        // KeyAgreements
        for key_agreement in get_deprecated_key_agreements() {
            deprecated_algorithms.push(Algorithm::KeyAgreement(key_agreement));
        }
        deprecated_algorithms
    }

    fn get_selection_non_deprecated_algorithms() -> Vec<Algorithm> {
        let mut selection_non_deprecated_algorithms: Vec<Algorithm> = vec![];
        // Hashes
        for hash in get_selection_non_deprecated_hashes() {
            selection_non_deprecated_algorithms.push(Algorithm::Hash(hash));
        }

        // Macs
        for mac in get_selection_non_deprecated_macs() {
            selection_non_deprecated_algorithms.push(Algorithm::Mac(mac));
        }

        // Cipher
        for cipher in get_selection_non_deprecated_ciphers() {
            selection_non_deprecated_algorithms.push(Algorithm::Cipher(cipher));
        }
        // Aead
        for aead in get_selection_non_deprecated_aeads() {
            selection_non_deprecated_algorithms.push(Algorithm::Aead(aead));
        }

        // AsymmetricSignatures
        for asymm_sig in get_selection_non_deprecated_asymmetric_signatures() {
            selection_non_deprecated_algorithms.push(Algorithm::AsymmetricSignature(asymm_sig));
        }

        // AsymmetricEncryptions
        for asymm_enc in get_selection_non_deprecated_asymmetric_encryptions() {
            selection_non_deprecated_algorithms.push(Algorithm::AsymmetricEncryption(asymm_enc));
        }

        // KeyDerivations
        for key_derv in get_selection_non_deprecated_key_derivations() {
            selection_non_deprecated_algorithms.push(Algorithm::KeyDerivation(key_derv));
        }

        // KeyAgreements
        for key_agreement in get_selection_non_deprecated_key_agreements() {
            selection_non_deprecated_algorithms.push(Algorithm::KeyAgreement(key_agreement));
        }
        selection_non_deprecated_algorithms
    }
    #[test]
    fn deprecated_algorithms() {
        for algo in get_deprecated_algorithms() {
            assert!(is_algorithm_deprecated(algo), "algorithm: {:?}", algo);
        }
    }

    #[test]
    fn non_deprecated_algorithms() {
        for algo in get_selection_non_deprecated_algorithms() {
            assert!(!is_algorithm_deprecated(algo), "algorithm: {:?}", algo);
        }
    }
}
