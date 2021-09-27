#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(string, repeated, tag="1")]
    pub clients: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
