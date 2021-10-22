#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrepareKeyAttestationParams {
    #[prost(oneof="prepare_key_attestation_params::Mechanism", tags="1")]
    pub mechanism: ::core::option::Option<prepare_key_attestation_params::Mechanism>,
}
/// Nested message and enum types in `PrepareKeyAttestationParams`.
pub mod prepare_key_attestation_params {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ActivateCredential {
        #[prost(string, tag="1")]
        pub attested_key_name: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub attesting_key_name: ::prost::alloc::string::String,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Mechanism {
        #[prost(message, tag="1")]
        ActivateCredential(ActivateCredential),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(message, optional, tag="1")]
    pub parameters: ::core::option::Option<PrepareKeyAttestationParams>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrepareKeyAttestationOutput {
    #[prost(oneof="prepare_key_attestation_output::Mechanism", tags="1")]
    pub mechanism: ::core::option::Option<prepare_key_attestation_output::Mechanism>,
}
/// Nested message and enum types in `PrepareKeyAttestationOutput`.
pub mod prepare_key_attestation_output {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ActivateCredential {
        #[prost(bytes="vec", tag="1")]
        pub name: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="2")]
        pub public: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="3")]
        pub attesting_key_pub: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Mechanism {
        #[prost(message, tag="1")]
        ActivateCredential(ActivateCredential),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Result {
    #[prost(message, optional, tag="1")]
    pub output: ::core::option::Option<PrepareKeyAttestationOutput>,
}
