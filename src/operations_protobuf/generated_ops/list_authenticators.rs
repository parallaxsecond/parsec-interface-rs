#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthenticatorInfo {
    #[prost(string, tag="1")]
    pub description: ::prost::alloc::string::String,
    #[prost(uint32, tag="2")]
    pub version_maj: u32,
    #[prost(uint32, tag="3")]
    pub version_min: u32,
    #[prost(uint32, tag="4")]
    pub version_rev: u32,
    #[prost(uint32, tag="5")]
    pub id: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(message, repeated, tag="1")]
    pub authenticators: ::prost::alloc::vec::Vec<AuthenticatorInfo>,
}
