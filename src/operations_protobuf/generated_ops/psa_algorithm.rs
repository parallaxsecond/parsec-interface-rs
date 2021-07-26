#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Algorithm {
    #[prost(oneof="algorithm::Variant", tags="1, 2, 3, 4, 5, 6, 7, 8, 9")]
    pub variant: ::std::option::Option<algorithm::Variant>,
}
pub mod algorithm {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct None {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Mac {
        #[prost(oneof="mac::Variant", tags="1, 2")]
        pub variant: ::std::option::Option<mac::Variant>,
    }
    pub mod mac {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct FullLength {
            #[prost(oneof="full_length::Variant", tags="1, 2, 3")]
            pub variant: ::std::option::Option<full_length::Variant>,
        }
        pub mod full_length {
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Hmac {
                #[prost(enumeration="super::super::Hash", tag="1")]
                pub hash_alg: i32,
            }
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct CbcMac {
            }
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Cmac {
            }
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum Variant {
                #[prost(message, tag="1")]
                Hmac(Hmac),
                #[prost(message, tag="2")]
                CbcMac(CbcMac),
                #[prost(message, tag="3")]
                Cmac(Cmac),
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Truncated {
            #[prost(message, optional, tag="1")]
            pub mac_alg: ::std::option::Option<FullLength>,
            #[prost(uint32, tag="2")]
            pub mac_length: u32,
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Variant {
            #[prost(message, tag="1")]
            FullLength(FullLength),
            #[prost(message, tag="2")]
            Truncated(Truncated),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Aead {
        #[prost(oneof="aead::Variant", tags="1, 2")]
        pub variant: ::std::option::Option<aead::Variant>,
    }
    pub mod aead {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct AeadWithShortenedTag {
            #[prost(enumeration="AeadWithDefaultLengthTag", tag="1")]
            pub aead_alg: i32,
            #[prost(uint32, tag="2")]
            pub tag_length: u32,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum AeadWithDefaultLengthTag {
            /// This default variant should not be used.
            None = 0,
            Ccm = 1,
            Gcm = 2,
            Chacha20Poly1305 = 3,
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Variant {
            #[prost(enumeration="AeadWithDefaultLengthTag", tag="1")]
            AeadWithDefaultLengthTag(i32),
            #[prost(message, tag="2")]
            AeadWithShortenedTag(AeadWithShortenedTag),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AsymmetricSignature {
        #[prost(oneof="asymmetric_signature::Variant", tags="1, 2, 3, 4, 5, 6")]
        pub variant: ::std::option::Option<asymmetric_signature::Variant>,
    }
    pub mod asymmetric_signature {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct SignHash {
            #[prost(oneof="sign_hash::Variant", tags="1, 2")]
            pub variant: ::std::option::Option<sign_hash::Variant>,
        }
        pub mod sign_hash {
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Any {
            }
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum Variant {
                #[prost(message, tag="1")]
                Any(Any),
                #[prost(enumeration="super::super::Hash", tag="2")]
                Specific(i32),
            }
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct RsaPkcs1v15Sign {
            #[prost(message, optional, tag="1")]
            pub hash_alg: ::std::option::Option<SignHash>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct RsaPkcs1v15SignRaw {
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct RsaPss {
            #[prost(message, optional, tag="1")]
            pub hash_alg: ::std::option::Option<SignHash>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Ecdsa {
            #[prost(message, optional, tag="1")]
            pub hash_alg: ::std::option::Option<SignHash>,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct EcdsaAny {
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct DeterministicEcdsa {
            #[prost(message, optional, tag="1")]
            pub hash_alg: ::std::option::Option<SignHash>,
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Variant {
            #[prost(message, tag="1")]
            RsaPkcs1v15Sign(RsaPkcs1v15Sign),
            #[prost(message, tag="2")]
            RsaPkcs1v15SignRaw(RsaPkcs1v15SignRaw),
            #[prost(message, tag="3")]
            RsaPss(RsaPss),
            #[prost(message, tag="4")]
            Ecdsa(Ecdsa),
            #[prost(message, tag="5")]
            EcdsaAny(EcdsaAny),
            #[prost(message, tag="6")]
            DeterministicEcdsa(DeterministicEcdsa),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AsymmetricEncryption {
        #[prost(oneof="asymmetric_encryption::Variant", tags="1, 2")]
        pub variant: ::std::option::Option<asymmetric_encryption::Variant>,
    }
    pub mod asymmetric_encryption {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct RsaPkcs1v15Crypt {
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct RsaOaep {
            #[prost(enumeration="super::Hash", tag="1")]
            pub hash_alg: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Variant {
            #[prost(message, tag="1")]
            RsaPkcs1v15Crypt(RsaPkcs1v15Crypt),
            #[prost(message, tag="2")]
            RsaOaep(RsaOaep),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct KeyAgreement {
        #[prost(oneof="key_agreement::Variant", tags="1, 2")]
        pub variant: ::std::option::Option<key_agreement::Variant>,
    }
    pub mod key_agreement {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct WithKeyDerivation {
            #[prost(enumeration="Raw", tag="1")]
            pub ka_alg: i32,
            #[prost(message, optional, tag="2")]
            pub kdf_alg: ::std::option::Option<super::KeyDerivation>,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Raw {
            /// This default variant should not be used.
            None = 0,
            Ffdh = 1,
            Ecdh = 2,
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Variant {
            #[prost(enumeration="Raw", tag="1")]
            Raw(i32),
            #[prost(message, tag="2")]
            WithKeyDerivation(WithKeyDerivation),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct KeyDerivation {
        #[prost(oneof="key_derivation::Variant", tags="1, 2, 3")]
        pub variant: ::std::option::Option<key_derivation::Variant>,
    }
    pub mod key_derivation {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Hkdf {
            #[prost(enumeration="super::Hash", tag="1")]
            pub hash_alg: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Tls12Prf {
            #[prost(enumeration="super::Hash", tag="1")]
            pub hash_alg: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Tls12PskToMs {
            #[prost(enumeration="super::Hash", tag="1")]
            pub hash_alg: i32,
        }
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Variant {
            #[prost(message, tag="1")]
            Hkdf(Hkdf),
            #[prost(message, tag="2")]
            Tls12Prf(Tls12Prf),
            #[prost(message, tag="3")]
            Tls12PskToMs(Tls12PskToMs),
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Hash {
        /// This default variant should not be used.
        None = 0,
        Md2 = 1,
        Md4 = 2,
        Md5 = 3,
        Ripemd160 = 4,
        Sha1 = 5,
        Sha224 = 6,
        Sha256 = 7,
        Sha384 = 8,
        Sha512 = 9,
        Sha512224 = 10,
        Sha512256 = 11,
        Sha3224 = 12,
        Sha3256 = 13,
        Sha3384 = 14,
        Sha3512 = 15,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Cipher {
        /// This default variant should not be used.
        None = 0,
        StreamCipher = 1,
        Ctr = 2,
        Cfb = 3,
        Ofb = 4,
        Xts = 5,
        EcbNoPadding = 6,
        CbcNoPadding = 7,
        CbcPkcs7 = 8,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Variant {
        #[prost(message, tag="1")]
        None(None),
        #[prost(enumeration="Hash", tag="2")]
        Hash(i32),
        #[prost(message, tag="3")]
        Mac(Mac),
        #[prost(enumeration="Cipher", tag="4")]
        Cipher(i32),
        #[prost(message, tag="5")]
        Aead(Aead),
        #[prost(message, tag="6")]
        AsymmetricSignature(AsymmetricSignature),
        #[prost(message, tag="7")]
        AsymmetricEncryption(AsymmetricEncryption),
        #[prost(message, tag="8")]
        KeyAgreement(KeyAgreement),
        #[prost(message, tag="9")]
        KeyDerivation(KeyDerivation),
    }
}
