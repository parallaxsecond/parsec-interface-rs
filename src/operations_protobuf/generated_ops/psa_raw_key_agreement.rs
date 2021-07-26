#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(enumeration="super::psa_algorithm::algorithm::key_agreement::Raw", tag="1")]
    pub alg: i32,
    #[prost(string, tag="2")]
    pub private_key_name: std::string::String,
    #[prost(bytes, tag="3")]
    pub peer_key: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes, tag="1")]
    pub shared_secret: std::vec::Vec<u8>,
}
