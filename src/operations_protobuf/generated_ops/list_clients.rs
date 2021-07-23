#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(string, repeated, tag="1")]
    pub clients: ::std::vec::Vec<std::string::String>,
}
