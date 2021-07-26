#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(bytes, tag="1")]
    pub data: std::vec::Vec<u8>,
}
