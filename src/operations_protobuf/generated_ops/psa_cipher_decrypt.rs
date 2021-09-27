#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: ::prost::alloc::string::String,
    #[prost(enumeration="super::psa_algorithm::algorithm::Cipher", tag="2")]
    pub alg: i32,
    #[prost(bytes="vec", tag="3")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes="vec", tag="1")]
    pub plaintext: ::prost::alloc::vec::Vec<u8>,
}
