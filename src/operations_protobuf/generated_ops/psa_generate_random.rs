#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(uint64, tag="1")]
    pub size: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes="vec", tag="1")]
    pub random_bytes: ::prost::alloc::vec::Vec<u8>,
}
