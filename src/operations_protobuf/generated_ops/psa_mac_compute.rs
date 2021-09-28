#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub alg: ::core::option::Option<super::psa_algorithm::algorithm::Mac>,
    #[prost(bytes="vec", tag="3")]
    pub input: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes="vec", tag="1")]
    pub mac: ::prost::alloc::vec::Vec<u8>,
}
