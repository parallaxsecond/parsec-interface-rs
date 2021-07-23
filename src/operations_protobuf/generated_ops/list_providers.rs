#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProviderInfo {
    #[prost(string, tag="1")]
    pub uuid: std::string::String,
    #[prost(string, tag="2")]
    pub description: std::string::String,
    #[prost(string, tag="3")]
    pub vendor: std::string::String,
    #[prost(uint32, tag="4")]
    pub version_maj: u32,
    #[prost(uint32, tag="5")]
    pub version_min: u32,
    #[prost(uint32, tag="6")]
    pub version_rev: u32,
    #[prost(uint32, tag="7")]
    pub id: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(message, repeated, tag="1")]
    pub providers: ::std::vec::Vec<ProviderInfo>,
}
