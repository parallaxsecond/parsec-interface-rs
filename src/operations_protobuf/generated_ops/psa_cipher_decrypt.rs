#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: std::string::String,
    #[prost(enumeration="super::psa_algorithm::algorithm::Cipher", tag="2")]
    pub alg: i32,
    #[prost(bytes, tag="3")]
    pub ciphertext: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes, tag="1")]
    pub plaintext: std::vec::Vec<u8>,
}
