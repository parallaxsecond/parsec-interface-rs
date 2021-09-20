#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(enumeration="CheckType", tag="1")]
    pub check_type: i32,
    #[prost(message, optional, tag="2")]
    pub attributes: ::std::option::Option<super::psa_key_attributes::KeyAttributes>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CheckType {
    ChecktypeNone = 0,
    Use = 1,
    Generate = 2,
    Import = 3,
    Derive = 4,
}
