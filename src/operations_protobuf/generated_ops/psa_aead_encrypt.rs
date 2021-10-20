#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub alg: ::core::option::Option<super::psa_algorithm::algorithm::Aead>,
    #[prost(bytes="vec", tag="3")]
    pub nonce: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub additional_data: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="5")]
    pub plaintext: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes="vec", tag="1")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
}
