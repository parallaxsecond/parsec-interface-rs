// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # DeleteClient operation
//!
//! Delete all data a client own in Parsec.

/// Native object for client deleting operation.
#[derive(Clone, Debug)]
pub struct Operation {
    /// A client application name.
    pub client: String,
}

/// Native object for client deleting result.
#[derive(Copy, Clone, Debug)]
pub struct Result;
