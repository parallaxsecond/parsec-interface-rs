// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::list_clients::{Operation as OperationProto, Result as ResultProto};
use crate::operations::list_clients::{Operation, Result};

impl From<OperationProto> for Operation {
    fn from(_proto_op: OperationProto) -> Self {
        Operation {}
    }
}

impl From<Operation> for OperationProto {
    fn from(_op: Operation) -> Self {
        Default::default()
    }
}

impl From<ResultProto> for Result {
    fn from(proto_op: ResultProto) -> Self {
        Result {
            clients: proto_op.clients,
        }
    }
}

impl From<Result> for ResultProto {
    fn from(op: Result) -> Self {
        ResultProto {
            clients: op.clients,
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::list_clients::Result as ResultProto;
    use crate::operations::list_clients::Result;

    #[test]
    fn proto_to_resp() {
        let mut proto: ResultProto = Default::default();

        proto.clients.push(String::from("toto"));

        let resp: Result = proto.into();

        assert_eq!(resp.clients.len(), 1);
        assert_eq!(resp.clients[0], String::from("toto"));
    }

    #[test]
    fn resp_to_proto() {
        let resp: Result = Result {
            clients: vec![String::from("toto")],
        };

        let proto: ResultProto = resp.into();

        assert_eq!(proto.clients.len(), 1);
        assert_eq!(proto.clients[0], String::from("toto"));
    }
}
