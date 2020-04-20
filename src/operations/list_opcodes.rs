// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # ListOpcodes operation
//!
//! List the opcodes supported by the provider.

use crate::requests::{Opcode, ProviderID};
use std::collections::HashSet;

/// Native object for opcode listing operation.
#[derive(Copy, Clone, Debug)]
pub struct Operation {
    /// Provider for which the supported opcodes are requsted.
    pub provider_id: ProviderID,
}

/// Native object for opcode listing result.
#[derive(Debug)]
pub struct Result {
    /// `opcodes` holds a list of opcodes supported by the provider identified in
    /// the request.
    pub opcodes: HashSet<Opcode>,
}
