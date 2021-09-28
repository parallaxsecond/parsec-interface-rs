#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(enumeration="super::psa_algorithm::algorithm::key_agreement::Raw", tag="1")]
    pub alg: i32,
    #[prost(string, tag="2")]
    pub private_key_name: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="3")]
    pub peer_key: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes="vec", tag="1")]
    pub shared_secret: ::prost::alloc::vec::Vec<u8>,
}
