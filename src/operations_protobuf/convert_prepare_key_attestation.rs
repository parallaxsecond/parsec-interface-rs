// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::prepare_key_attestation::{
    prepare_key_attestation_output, prepare_key_attestation_params, Operation as OperationProto,
    PrepareKeyAttestationOutput, PrepareKeyAttestationParams, Result as ResultProto,
};
use crate::operations::prepare_key_attestation::{Operation, Result};
use crate::requests::ResponseStatus;
use log::error;
use std::convert::TryFrom;

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        match op {
            Operation::ActivateCredential {
                attested_key_name,
                attesting_key_name,
            } => Ok(OperationProto {
                parameters: Some(PrepareKeyAttestationParams {
                    mechanism: Some(
                        prepare_key_attestation_params::Mechanism::ActivateCredential(
                            prepare_key_attestation_params::ActivateCredential {
                                attested_key_name,
                                attesting_key_name: attesting_key_name.unwrap_or_default(),
                            },
                        ),
                    ),
                }),
            }),
        }
    }
}

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(op: OperationProto) -> std::result::Result<Self, Self::Error> {
        match op {
            OperationProto {
                parameters:
                    Some(PrepareKeyAttestationParams {
                        mechanism:
                            Some(prepare_key_attestation_params::Mechanism::ActivateCredential(
                                prepare_key_attestation_params::ActivateCredential {
                                    attested_key_name,
                                    attesting_key_name,
                                },
                            )),
                    }),
            } => Ok(Operation::ActivateCredential {
                attested_key_name,
                attesting_key_name: if attesting_key_name.is_empty() {
                    None
                } else {
                    Some(attesting_key_name)
                },
            }),
            _ => {
                error!("The encoding of the operation does not follow the expected pattern");
                Err(ResponseStatus::InvalidEncoding)
            }
        }
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(op: Result) -> std::result::Result<Self, Self::Error> {
        match op {
            Result::ActivateCredential {
                name,
                public,
                attesting_key_pub,
            } => Ok(ResultProto {
                output: Some(PrepareKeyAttestationOutput {
                    mechanism: Some(
                        prepare_key_attestation_output::Mechanism::ActivateCredential(
                            prepare_key_attestation_output::ActivateCredential {
                                name: name.to_vec(),
                                public: public.to_vec(),
                                attesting_key_pub: attesting_key_pub.to_vec(),
                            },
                        ),
                    ),
                }),
            }),
        }
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(op: ResultProto) -> std::result::Result<Self, Self::Error> {
        match op {
            ResultProto {
                output:
                    Some(PrepareKeyAttestationOutput {
                        mechanism:
                            Some(prepare_key_attestation_output::Mechanism::ActivateCredential(
                                prepare_key_attestation_output::ActivateCredential {
                                    name,
                                    public,
                                    attesting_key_pub,
                                },
                            )),
                    }),
            } => Ok(Result::ActivateCredential {
                name: name.into(),
                public: public.into(),
                attesting_key_pub: attesting_key_pub.into(),
            }),
            _ => {
                error!("The encoding of the operation does not follow the expected pattern");
                Err(ResponseStatus::InvalidEncoding)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::prepare_key_attestation::{
        prepare_key_attestation_output, prepare_key_attestation_params,
        Operation as OperationProto, PrepareKeyAttestationOutput, PrepareKeyAttestationParams,
        Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{
        prepare_key_attestation::Operation, prepare_key_attestation::Result, NativeOperation,
        NativeResult,
    };
    use crate::requests::Opcode;
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn prepare_key_attestation_op_from_proto() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");

        let proto = OperationProto {
            parameters: Some(PrepareKeyAttestationParams {
                mechanism: Some(
                    prepare_key_attestation_params::Mechanism::ActivateCredential(
                        prepare_key_attestation_params::ActivateCredential {
                            attested_key_name: op_attested_key_name.clone(),
                            attesting_key_name: op_attesting_key_name.clone(),
                        },
                    ),
                ),
            }),
        };

        let op: Operation = proto.try_into().expect("Conversion failed");

        let Operation::ActivateCredential {
            attested_key_name,
            attesting_key_name,
        } = op;

        assert_eq!(attested_key_name, op_attested_key_name);
        assert_eq!(
            attesting_key_name.expect("Attesting key name was empty"),
            op_attesting_key_name
        );
    }

    #[test]
    fn prepare_key_attestation_proto_no_attesting() {
        let op_attested_key_name = String::from("attested key name");

        let proto = OperationProto {
            parameters: Some(PrepareKeyAttestationParams {
                mechanism: Some(
                    prepare_key_attestation_params::Mechanism::ActivateCredential(
                        prepare_key_attestation_params::ActivateCredential {
                            attested_key_name: op_attested_key_name,
                            attesting_key_name: String::new(),
                        },
                    ),
                ),
            }),
        };

        let op: Operation = proto.try_into().expect("Conversion failed");

        let Operation::ActivateCredential {
            attesting_key_name, ..
        } = op;

        assert!(attesting_key_name.is_none());
    }

    #[test]
    fn prepare_key_attestation_op_to_proto() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");

        let op: Operation = Operation::ActivateCredential {
            attested_key_name: op_attested_key_name.clone(),
            attesting_key_name: Some(op_attesting_key_name.clone()),
        };

        let proto: OperationProto = op.try_into().expect("Conversion failed");

        if let OperationProto {
            parameters:
                Some(PrepareKeyAttestationParams {
                    mechanism:
                        Some(prepare_key_attestation_params::Mechanism::ActivateCredential(
                            prepare_key_attestation_params::ActivateCredential {
                                attested_key_name,
                                attesting_key_name,
                            },
                        )),
                }),
        } = proto
        {
            assert_eq!(attested_key_name, op_attested_key_name);
            assert_eq!(attesting_key_name, op_attesting_key_name);
        }
    }

    #[test]
    fn prepare_key_attestation_op_no_attesting() {
        let op_attested_key_name = String::from("attested key name");

        let op: Operation = Operation::ActivateCredential {
            attested_key_name: op_attested_key_name,
            attesting_key_name: None,
        };

        let proto: OperationProto = op.try_into().expect("Conversion failed");

        if let OperationProto {
            parameters:
                Some(PrepareKeyAttestationParams {
                    mechanism:
                        Some(prepare_key_attestation_params::Mechanism::ActivateCredential(
                            prepare_key_attestation_params::ActivateCredential {
                                attesting_key_name,
                                ..
                            },
                        )),
                }),
        } = proto
        {
            assert_eq!(attesting_key_name, String::new());
        }
    }

    #[test]
    fn prepare_key_attestation_op_e2e() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");

        let op: Operation = Operation::ActivateCredential {
            attested_key_name: op_attested_key_name,
            attesting_key_name: Some(op_attesting_key_name),
        };

        let body = CONVERTER
            .operation_to_body(NativeOperation::PrepareKeyAttestation(op))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_operation(body, Opcode::PrepareKeyAttestation)
            .expect("Failed to convert to operation");
    }

    #[test]
    fn prepare_key_attestation_resp_to_proto() {
        let resp_name = vec![0xff; 32];
        let resp_public = vec![0xcc; 32];
        let resp_attesting_key_pub = vec![0x22; 32];

        let result = Result::ActivateCredential {
            name: resp_name.clone().into(),
            public: resp_public.clone().into(),
            attesting_key_pub: resp_attesting_key_pub.clone().into(),
        };

        let proto: ResultProto = result.try_into().expect("Conversion failed");
        if let ResultProto {
            output:
                Some(PrepareKeyAttestationOutput {
                    mechanism:
                        Some(prepare_key_attestation_output::Mechanism::ActivateCredential(
                            prepare_key_attestation_output::ActivateCredential {
                                name,
                                public,
                                attesting_key_pub,
                            },
                        )),
                }),
        } = proto
        {
            assert_eq!(name, resp_name);
            assert_eq!(public, resp_public);
            assert_eq!(attesting_key_pub, resp_attesting_key_pub);
        }
    }

    #[test]
    fn prepare_key_attestation_resp_from_proto() {
        let resp_name = vec![0xff; 32];
        let resp_public = vec![0xcc; 32];
        let resp_attesting_key_pub = vec![0x22; 32];

        let proto = ResultProto {
            output: Some(PrepareKeyAttestationOutput {
                mechanism: Some(
                    prepare_key_attestation_output::Mechanism::ActivateCredential(
                        prepare_key_attestation_output::ActivateCredential {
                            name: resp_name.clone(),
                            public: resp_public.clone(),
                            attesting_key_pub: resp_attesting_key_pub.clone(),
                        },
                    ),
                ),
            }),
        };

        let result: Result = proto.try_into().expect("Conversion failed");

        let Result::ActivateCredential {
            name,
            public,
            attesting_key_pub,
        } = result;

        assert_eq!(name.to_vec(), resp_name);
        assert_eq!(public.to_vec(), resp_public);
        assert_eq!(attesting_key_pub.to_vec(), resp_attesting_key_pub);
    }

    #[test]
    fn prepare_key_attestation_resp_e2e() {
        let resp_name = vec![0xff; 32];
        let resp_public = vec![0xcc; 32];
        let resp_attesting_key_pub = vec![0x22; 32];

        let result = Result::ActivateCredential {
            name: resp_name.into(),
            public: resp_public.into(),
            attesting_key_pub: resp_attesting_key_pub.into(),
        };

        let body = CONVERTER
            .result_to_body(NativeResult::PrepareKeyAttestation(result))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_result(body, Opcode::PrepareKeyAttestation)
            .expect("Failed to convert to operation");
    }
}
