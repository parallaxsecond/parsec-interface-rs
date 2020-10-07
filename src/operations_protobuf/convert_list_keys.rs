// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::list_keys::{
    KeyInfo as KeyInfoProto, Operation as OperationProto, Result as ResultProto,
};
use crate::operations::list_keys::{KeyInfo, Operation, Result};
use crate::requests::{ProviderID, ResponseStatus};
use log::error;
use num::FromPrimitive;
use std::convert::{TryFrom, TryInto};

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(_proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        Ok(Operation {})
    }
}

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(_op: Operation) -> std::result::Result<Self, Self::Error> {
        Ok(Default::default())
    }
}

impl TryFrom<KeyInfoProto> for KeyInfo {
    type Error = ResponseStatus;

    fn try_from(proto_info: KeyInfoProto) -> std::result::Result<Self, Self::Error> {
        let id: ProviderID = match FromPrimitive::from_u32(proto_info.provider_id) {
            Some(id) => id,
            None => return Err(ResponseStatus::ProviderDoesNotExist),
        };

        let attributes = proto_info
            .attributes
            .ok_or_else(|| {
                error!("attributes field of KeyInfo protobuf message is empty.");
                ResponseStatus::InvalidEncoding
            })?
            .try_into()?;

        Ok(KeyInfo {
            provider_id: id,
            name: proto_info.name,
            attributes,
        })
    }
}

impl TryFrom<KeyInfo> for KeyInfoProto {
    type Error = ResponseStatus;

    fn try_from(info: KeyInfo) -> std::result::Result<Self, Self::Error> {
        Ok(KeyInfoProto {
            provider_id: info.provider_id as u32,
            name: info.name,
            attributes: Some(info.attributes.try_into()?),
        })
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultProto) -> std::result::Result<Self, Self::Error> {
        let mut keys: Vec<KeyInfo> = Vec::new();
        for key in proto_op.keys {
            keys.push(key.try_into()?);
        }

        Ok(Result { keys })
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(op: Result) -> std::result::Result<Self, Self::Error> {
        let mut keys: Vec<KeyInfoProto> = Vec::new();
        for key in op.keys {
            keys.push(key.try_into()?);
        }

        Ok(ResultProto { keys })
    }
}
