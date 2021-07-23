#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(uint64, tag="1")]
    pub size: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes, tag="1")]
    pub random_bytes: std::vec::Vec<u8>,
}
