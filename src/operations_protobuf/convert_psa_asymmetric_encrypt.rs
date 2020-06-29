// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::psa_asymmetric_encrypt::{
    Operation as OperationProto, Result as ResultProto,
};
use crate::operations::psa_asymmetric_encrypt::{Operation, Result};
use crate::requests::ResponseStatus;
use log::error;
use std::convert::{TryFrom, TryInto};
use zeroize::Zeroizing;

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        let salt = match proto_op.salt.len() {
            0 => None,
            _ => Some(Zeroizing::new(proto_op.salt)),
        };

        Ok(Operation {
            key_name: proto_op.key_name,
            alg: proto_op
                .alg
                .ok_or_else(|| {
                    error!("alg field of PsaAsymmetricEncrypt::Operation message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
            plaintext: proto_op.plaintext.into(),
            salt,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        let alg = Some(op.alg.try_into()?);
        let salt = match op.salt {
            Some(salt) => salt.to_vec(),
            None => vec![],
        };
        Ok(OperationProto {
            key_name: op.key_name,
            alg,
            plaintext: op.plaintext.to_vec(),
            salt,
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_result: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {
            ciphertext: proto_result.ciphertext.into(),
        })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(ResultProto {
            ciphertext: result.ciphertext.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::psa_algorithm as algorithm_proto;
    use super::super::generated_ops::psa_asymmetric_encrypt::{
        Operation as OperationProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::psa_algorithm::AsymmetricEncryption;
    use crate::operations::psa_asymmetric_encrypt::{Operation, Result};
    use std::convert::TryInto;
    static CONVERTER: ProtobufConverter = ProtobufConverter {};
    use crate::operations::{NativeOperation, NativeResult};
    use crate::requests::{request::RequestBody, response::ResponseBody, Opcode};

    #[test]
    fn asym_proto_to_op() {
        let mut proto: OperationProto = Default::default();
        let message = vec![0x11, 0x22, 0x33];
        let key_name = "test name".to_string();
        let salt: Vec<u8> = vec![];
        proto.plaintext = message.clone();
        proto.alg = Some(algorithm_proto::algorithm::AsymmetricEncryption {
            variant: Some(
                algorithm_proto::algorithm::asymmetric_encryption::Variant::RsaPkcs1v15Crypt(
                    algorithm_proto::algorithm::asymmetric_encryption::RsaPkcs1v15Crypt {},
                ),
            ),
        });
        proto.key_name = key_name.clone();
        proto.salt = salt;

        let op: Operation = proto.try_into().expect("Failed to convert");

        assert_eq!(*op.plaintext, message);
        assert_eq!(op.key_name, key_name);
        assert_eq!(op.salt, None);
    }

    #[test]
    fn asym_op_to_proto() {
        let message = vec![0x11, 0x22, 0x33];
        let key_name = "test name".to_string();

        let op = Operation {
            plaintext: message.clone().into(),
            alg: AsymmetricEncryption::RsaPkcs1v15Crypt,
            key_name: key_name.clone(),
            salt: None,
        };

        let proto: OperationProto = op.try_into().expect("Failed to convert");

        assert_eq!(proto.plaintext, message);
        assert_eq!(proto.key_name, key_name);
        assert_eq!(proto.salt, vec![]);
    }

    #[test]
    fn asym_proto_to_resp() {
        let mut proto: ResultProto = Default::default();
        let ciphertext = vec![0x11, 0x22, 0x33];
        proto.ciphertext = ciphertext.clone();

        let result: Result = proto.try_into().expect("Failed to convert");

        assert_eq!(*result.ciphertext, ciphertext);
    }

    #[test]
    fn asym_resp_to_proto() {
        let ciphertext = vec![0x11, 0x22, 0x33];
        let result = Result {
            ciphertext: ciphertext.clone().into(),
        };

        let proto: ResultProto = result.try_into().expect("Failed to convert");

        assert_eq!(proto.ciphertext, ciphertext);
    }

    #[test]
    fn psa_encrypt_message_op_e2e() {
        let name = "test name".to_string();
        let op = Operation {
            key_name: name,
            alg: AsymmetricEncryption::RsaPkcs1v15Crypt,
            plaintext: vec![0x11, 0x22, 0x33].into(),
            salt: None,
        };

        let body = CONVERTER
            .operation_to_body(NativeOperation::PsaAsymmetricEncrypt(op))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_operation(body, Opcode::PsaAsymmetricEncrypt)
            .expect("Failed to convert to operation");
    }

    #[test]
    fn resp_asym_encrypt_e2e() {
        let result = Result {
            ciphertext: vec![0x11, 0x22, 0x33].into(),
        };
        let body = CONVERTER
            .result_to_body(NativeResult::PsaAsymmetricEncrypt(result))
            .expect("Failed to convert request");

        assert!(CONVERTER
            .body_to_result(body, Opcode::PsaAsymmetricEncrypt)
            .is_ok());
    }

    #[test]
    fn result_from_mangled_resp_body() {
        let resp_body =
            ResponseBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(CONVERTER
            .body_to_result(resp_body, Opcode::PsaAsymmetricEncrypt)
            .is_err());
    }

    #[test]
    fn op_from_mangled_req_body() {
        let req_body =
            RequestBody::from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        assert!(CONVERTER
            .body_to_operation(req_body, Opcode::PsaAsymmetricEncrypt)
            .is_err());
    }
}
