// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::delete_client::{Operation as OperationProto, Result as ResultProto};
use crate::operations::delete_client::{Operation, Result};

impl From<OperationProto> for Operation {
    fn from(proto_op: OperationProto) -> Self {
        Operation {
            client: proto_op.client,
        }
    }
}

impl From<Operation> for OperationProto {
    fn from(op: Operation) -> Self {
        OperationProto { client: op.client }
    }
}

impl From<ResultProto> for Result {
    fn from(_proto_op: ResultProto) -> Self {
        Result {}
    }
}

impl From<Result> for ResultProto {
    fn from(_op: Result) -> Self {
        ResultProto {}
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::delete_client::Operation as OperationProto;
    use crate::operations::delete_client::Operation;

    #[test]
    fn proto_to_resp() {
        let proto = OperationProto {
            client: String::from("toto"),
        };

        let resp: Operation = proto.into();

        assert_eq!(resp.client, String::from("toto"));
    }

    #[test]
    fn resp_to_proto() {
        let resp: Operation = Operation {
            client: String::from("toto"),
        };

        let proto: OperationProto = resp.into();

        assert_eq!(proto.client, String::from("toto"));
    }
}
