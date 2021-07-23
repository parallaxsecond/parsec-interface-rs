#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: std::string::String,
    #[prost(message, optional, tag="2")]
    pub alg: ::std::option::Option<super::psa_algorithm::algorithm::Aead>,
    #[prost(bytes, tag="3")]
    pub nonce: std::vec::Vec<u8>,
    #[prost(bytes, tag="4")]
    pub additional_data: std::vec::Vec<u8>,
    #[prost(bytes, tag="5")]
    pub plaintext: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes, tag="1")]
    pub ciphertext: std::vec::Vec<u8>,
}
