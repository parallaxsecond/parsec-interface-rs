#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: std::string::String,
    #[prost(message, optional, tag="2")]
    pub attributes: ::std::option::Option<super::psa_key_attributes::KeyAttributes>,
    #[prost(bytes, tag="3")]
    pub data: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
}
