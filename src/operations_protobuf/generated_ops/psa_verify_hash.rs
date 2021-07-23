#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: std::string::String,
    #[prost(message, optional, tag="2")]
    pub alg: ::std::option::Option<super::psa_algorithm::algorithm::AsymmetricSignature>,
    #[prost(bytes, tag="3")]
    pub hash: std::vec::Vec<u8>,
    #[prost(bytes, tag="4")]
    pub signature: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
}
