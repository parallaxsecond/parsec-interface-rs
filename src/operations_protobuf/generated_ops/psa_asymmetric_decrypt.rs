#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: std::string::String,
    #[prost(message, optional, tag="2")]
    pub alg: ::std::option::Option<super::psa_algorithm::algorithm::AsymmetricEncryption>,
    #[prost(bytes, tag="3")]
    pub ciphertext: std::vec::Vec<u8>,
    #[prost(bytes, tag="4")]
    pub salt: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes, tag="1")]
    pub plaintext: std::vec::Vec<u8>,
}
