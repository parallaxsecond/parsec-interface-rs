#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttestationMechanismParams {
    #[prost(oneof="attestation_mechanism_params::Mechanism", tags="1")]
    pub mechanism: ::core::option::Option<attestation_mechanism_params::Mechanism>,
}
/// Nested message and enum types in `AttestationMechanismParams`.
pub mod attestation_mechanism_params {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ActivateCredential {
        #[prost(bytes="vec", tag="1")]
        pub credential_blob: ::prost::alloc::vec::Vec<u8>,
        #[prost(bytes="vec", tag="2")]
        pub secret: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Mechanism {
        #[prost(message, tag="1")]
        ActivateCredential(ActivateCredential),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(string, tag="1")]
    pub attested_key_name: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub parameters: ::core::option::Option<AttestationMechanismParams>,
    #[prost(string, tag="3")]
    pub attesting_key_name: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttestationOutput {
    #[prost(oneof="attestation_output::Mechanism", tags="1")]
    pub mechanism: ::core::option::Option<attestation_output::Mechanism>,
}
/// Nested message and enum types in `AttestationOutput`.
pub mod attestation_output {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ActivateCredential {
        #[prost(bytes="vec", tag="1")]
        pub credential: ::prost::alloc::vec::Vec<u8>,
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
    pub output: ::core::option::Option<AttestationOutput>,
}
