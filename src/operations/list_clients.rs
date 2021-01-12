// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # ListClients operation
//!
//! Lists all clients owning data in Parsec.

/// Native object for client listing operation.
#[derive(Copy, Clone, Debug)]
pub struct Operation;

/// Native object for client listing result.
#[derive(Debug)]
pub struct Result {
    /// A list of client application names.
    pub clients: Vec<String>,
}
