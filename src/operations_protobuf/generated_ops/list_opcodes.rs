#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(uint32, tag="1")]
    pub provider_id: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(uint32, repeated, tag="1")]
    pub opcodes: ::prost::alloc::vec::Vec<u32>,
}
