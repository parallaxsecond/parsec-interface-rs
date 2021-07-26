#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(enumeration="super::psa_algorithm::algorithm::Hash", tag="1")]
    pub alg: i32,
    #[prost(bytes, tag="2")]
    pub input: std::vec::Vec<u8>,
    #[prost(bytes, tag="3")]
    pub hash: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
}
