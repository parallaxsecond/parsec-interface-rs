#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyAttributes {
    #[prost(message, optional, tag="1")]
    pub key_type: ::core::option::Option<KeyType>,
    #[prost(uint32, tag="2")]
    pub key_bits: u32,
    #[prost(message, optional, tag="3")]
    pub key_policy: ::core::option::Option<KeyPolicy>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyType {
    #[prost(oneof="key_type::Variant", tags="1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14")]
    pub variant: ::core::option::Option<key_type::Variant>,
}
/// Nested message and enum types in `KeyType`.
pub mod key_type {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RawData {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Hmac {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Derive {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Aes {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Des {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Camellia {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Arc4 {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Chacha20 {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RsaPublicKey {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RsaKeyPair {
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct EccKeyPair {
        #[prost(enumeration="EccFamily", tag="1")]
        pub curve_family: i32,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct EccPublicKey {
        #[prost(enumeration="EccFamily", tag="1")]
        pub curve_family: i32,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DhKeyPair {
        #[prost(enumeration="DhFamily", tag="1")]
        pub group_family: i32,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DhPublicKey {
        #[prost(enumeration="DhFamily", tag="1")]
        pub group_family: i32,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum EccFamily {
        /// This default variant should not be used.
        None = 0,
        SecpK1 = 1,
        SecpR1 = 2,
        SecpR2 = 3,
        /// DEPRECATED for sect163k1 curve
        SectK1 = 4,
        /// DEPRECATED for sect163r1 curve
        SectR1 = 5,
        SectR2 = 6,
        /// DEPRECATED for brainpoolP160r1 curve
        BrainpoolPR1 = 7,
        Frp = 8,
        Montgomery = 9,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum DhFamily {
        Rfc7919 = 0,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Variant {
        #[prost(message, tag="1")]
        RawData(RawData),
        /// Symmetric keys
        #[prost(message, tag="2")]
        Hmac(Hmac),
        #[prost(message, tag="3")]
        Derive(Derive),
        #[prost(message, tag="4")]
        Aes(Aes),
        #[prost(message, tag="5")]
        Des(Des),
        #[prost(message, tag="6")]
        Camellia(Camellia),
        #[prost(message, tag="7")]
        Arc4(Arc4),
        #[prost(message, tag="8")]
        Chacha20(Chacha20),
        /// RSA keys
        #[prost(message, tag="9")]
        RsaPublicKey(RsaPublicKey),
        #[prost(message, tag="10")]
        RsaKeyPair(RsaKeyPair),
        /// Elliptic Curve keys
        #[prost(message, tag="11")]
        EccKeyPair(EccKeyPair),
        #[prost(message, tag="12")]
        EccPublicKey(EccPublicKey),
        /// Finite Field Diffie Hellman keys
        #[prost(message, tag="13")]
        DhKeyPair(DhKeyPair),
        #[prost(message, tag="14")]
        DhPublicKey(DhPublicKey),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyPolicy {
    #[prost(message, optional, tag="1")]
    pub key_usage_flags: ::core::option::Option<UsageFlags>,
    #[prost(message, optional, tag="2")]
    pub key_algorithm: ::core::option::Option<super::psa_algorithm::Algorithm>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UsageFlags {
    #[prost(bool, tag="1")]
    pub export: bool,
    #[prost(bool, tag="2")]
    pub copy: bool,
    #[prost(bool, tag="3")]
    pub cache: bool,
    #[prost(bool, tag="4")]
    pub encrypt: bool,
    #[prost(bool, tag="5")]
    pub decrypt: bool,
    #[prost(bool, tag="6")]
    pub sign_message: bool,
    #[prost(bool, tag="7")]
    pub verify_message: bool,
    #[prost(bool, tag="8")]
    pub sign_hash: bool,
    #[prost(bool, tag="9")]
    pub verify_hash: bool,
    #[prost(bool, tag="10")]
    pub derive: bool,
}
