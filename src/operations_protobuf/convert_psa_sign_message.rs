// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::psa_sign_message::{Operation as OperationProto, Result as ResultProto};
use crate::operations::psa_sign_message::{Operation, Result};
use crate::requests::ResponseStatus;
use log::error;
use std::convert::{TryFrom, TryInto};
use zeroize::Zeroizing;

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        let message = Zeroizing::new(proto_op.message);
        Ok(Operation {
            key_name: proto_op.key_name,
            alg: proto_op
                .alg
                .ok_or_else(|| {
                    error!("alg field of psa_sign_message::Operation message is empty.");
                    ResponseStatus::InvalidEncoding
                })?
                .try_into()?,
            message,
        })
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        let alg = Some(op.alg.try_into()?);
        Ok(OperationProto {
            key_name: op.key_name,
            alg,
            message: op.message.to_vec(),
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_result: ResultProto) -> std::result::Result<Self, Self::Error> {
        Ok(Result {
            signature: proto_result.signature.into(),
        })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(result: Result) -> std::result::Result<Self, Self::Error> {
        Ok(ResultProto {
            signature: result.signature.to_vec(),
        })
    }
}
