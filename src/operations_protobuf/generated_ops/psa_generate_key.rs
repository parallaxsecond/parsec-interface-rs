#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub key_name: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub attributes: ::core::option::Option<super::psa_key_attributes::KeyAttributes>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
}
