#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    /// Cast down to 8 bits
    #[prost(uint32, tag="1")]
    pub wire_protocol_version_maj: u32,
    /// Cast down to 8 bits
    #[prost(uint32, tag="2")]
    pub wire_protocol_version_min: u32,
}
