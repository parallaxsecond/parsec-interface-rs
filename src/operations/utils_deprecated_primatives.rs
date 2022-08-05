// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//!
//! # Utilities for checking deprecated primatives
//! # by PSA Crypto API 1.0.0

use psa_crypto::types::algorithm::*;
use psa_crypto::types::key;
use psa_crypto::types::key::Type;

fn get_deprecated_hashes() -> Vec<Hash> {
    vec![Hash::Md2, Hash::Md4, Hash::Md5, Hash::Sha1]
}

/// Check if hash is deprecated by PSA Crypto API
pub fn is_hash_deprecated(hash: Hash) -> bool {
    get_deprecated_hashes().contains(&hash)
}

/// Check if signhash is deprecated by PSA Crypto API
pub fn is_signhash_deprecated(signhash: SignHash) -> bool {
    match signhash {
        SignHash::Specific(hash) => is_hash_deprecated(hash),
        SignHash::Any => false,
    }
}

/// Check if any part of the mac is deprecated by PSA Crypto API
pub fn is_mac_deprecated(mac: Mac) -> bool {
    pub fn is_full_length_mac_deprecated(full_length_mac: FullLengthMac) -> bool {
        match full_length_mac {
            FullLengthMac::Hmac { hash_alg } => is_hash_deprecated(hash_alg),
            _ => false,
        }
    }
    match mac {
        Mac::FullLength(full_length_mac) => is_full_length_mac_deprecated(full_length_mac),
        Mac::Truncated { mac_alg, .. } => is_full_length_mac_deprecated(mac_alg),
    }
}

/// Check if any part of the cipher is deprecated by PSA Crypto API
pub fn is_cipher_deprecated(_cipher: Cipher) -> bool {
    false
}

/// Check if any part of the aead is deprecated by PSA Crypto API
pub fn is_aead_deprecated(_aead: Aead) -> bool {
    false
}

/// Check if any part of the asymmetric signature is deprecated by PSA Crypto API
pub fn is_asymmetric_signatiure_deprecated(asymm_sig: AsymmetricSignature) -> bool {
    match asymm_sig {
        AsymmetricSignature::RsaPkcs1v15Sign { hash_alg }
        | AsymmetricSignature::RsaPss { hash_alg }
        | AsymmetricSignature::Ecdsa { hash_alg }
        | AsymmetricSignature::DeterministicEcdsa { hash_alg } => is_signhash_deprecated(hash_alg),
        _ => false,
    }
}

/// Check if any part of the asymmetric encryption is deprecated by PSA Crypto API
pub fn is_asymmetric_encryption_deprecated(asymm_enc: AsymmetricEncryption) -> bool {
    match asymm_enc {
        AsymmetricEncryption::RsaOaep { hash_alg } => is_hash_deprecated(hash_alg),
        _ => false,
    }
}

/// Check if any part of the key agreement is deprecated by PSA Crypto API
pub fn is_key_agreement_deprecated(key_agreement: KeyAgreement) -> bool {
    match key_agreement {
        KeyAgreement::WithKeyDerivation { kdf_alg, .. } => is_key_derivation_deprecated(kdf_alg),
        _ => false,
    }
}

/// Check if any part of the key derivation is deprecated by PSA Crypto API
pub fn is_key_derivation_deprecated(keyderv: KeyDerivation) -> bool {
    match keyderv {
        KeyDerivation::Hkdf { hash_alg }
        | KeyDerivation::Tls12Prf { hash_alg }
        | KeyDerivation::Tls12PskToMs { hash_alg } => is_hash_deprecated(hash_alg),
    }
}

/// Check if any part of the algorithm is deprecated by PSA Crypto API
pub fn is_algorithm_deprecated(alg: Algorithm) -> bool {
    match alg {
        Algorithm::None => false,
        Algorithm::Hash(hash) => is_hash_deprecated(hash),
        Algorithm::Mac(mac) => is_mac_deprecated(mac),
        Algorithm::Cipher(cipher) => is_cipher_deprecated(cipher),
        Algorithm::Aead(aead) => is_aead_deprecated(aead),
        Algorithm::AsymmetricSignature(asymm_sig) => is_asymmetric_signatiure_deprecated(asymm_sig),
        Algorithm::AsymmetricEncryption(asymm_enc) => {
            is_asymmetric_encryption_deprecated(asymm_enc)
        }
        Algorithm::KeyAgreement(key_agreement) => is_key_agreement_deprecated(key_agreement),
        Algorithm::KeyDerivation(keyderv) => is_key_derivation_deprecated(keyderv),
    }
}

/// Return a list of deprecated keys (type, size) if size is None, then the key type is deprecated
fn get_deprecated_keys() -> Vec<(Type, Option<usize>)> {
    vec![
        (Type::Des, None),
        (Type::Arc4, None),
        (
            Type::EccPublicKey {
                curve_family: key::EccFamily::BrainpoolPR1,
            },
            Some(160),
        ),
        (
            Type::EccPublicKey {
                curve_family: key::EccFamily::SectR2,
            },
            None,
        ),
        (
            Type::EccPublicKey {
                curve_family: key::EccFamily::SectR1,
            },
            Some(163),
        ),
        (
            Type::EccPublicKey {
                curve_family: key::EccFamily::SectK1,
            },
            Some(163),
        ),
        (
            Type::EccPublicKey {
                curve_family: key::EccFamily::SecpR2,
            },
            None,
        ),
    ]
}

/// Check if the key or the key type is deprecated by PSA Crypto API
pub fn is_key_deprecated(key_type: Type, key_size: usize) -> bool {
    for (ktype, ksize) in get_deprecated_keys() {
        if ktype == key_type && (ksize.is_none() || ksize == Some(key_size)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn deprecated_keys() {
        let test_keys = vec![
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SecpR2,
                },
                160,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SectK1,
                },
                163,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SectR1,
                },
                163,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SectR2,
                },
                163,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::BrainpoolPR1,
                },
                160,
            ),
            (Type::Des, 56),
            (Type::Des, 56 * 2),
            (Type::Des, 56 * 3),
            (Type::Arc4, 40),
            (Type::Arc4, 2048),
        ];
        for (ktype, ksize) in test_keys {
            assert!(
                is_key_deprecated(ktype, ksize),
                "key: ({:?} : {:?})",
                ktype,
                ksize
            );
        }
    }

    #[test]
    fn non_deprecated_keys() {
        let test_keys = vec![
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SecpK1,
                },
                192,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SecpR1,
                },
                256,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SectK1,
                },
                239,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::SectR1,
                },
                409,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::BrainpoolPR1,
                },
                192,
            ),
            (
                Type::EccPublicKey {
                    curve_family: key::EccFamily::BrainpoolPR1,
                },
                256,
            ),
            (Type::Aes, 256),
            (Type::RsaPublicKey, 2048),
            (Type::Hmac, 128),
            (Type::Chacha20, 256),
        ];
        for (ktype, ksize) in test_keys {
            assert!(
                !is_key_deprecated(ktype, ksize),
                "key: ({:?} : {:?})",
                ktype,
                ksize
            );
        }
    }
}
