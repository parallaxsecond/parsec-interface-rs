#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(enumeration="super::psa_algorithm::algorithm::Hash", tag="1")]
    pub alg: i32,
    #[prost(bytes="vec", tag="2")]
    pub input: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
}
