// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # Ping operation
//!
//! The Ping operation is used to check if the service is alive and determine the highest wire
//! protocol version a client can use.

/// Native object for Ping operation.
#[derive(Copy, Clone, Debug)]
pub struct Operation;

/// Native object for Ping result.
///
/// The latest wire protocol version supported by the service. The version is represented as `x.y`
/// where `x` is the version major and `y` the version minor.
#[derive(Copy, Clone, Debug)]
pub struct Result {
    /// Supported latest wire protocol version major
    pub wire_protocol_version_maj: u8,
    /// Supported latest wire protocol version minor
    pub wire_protocol_version_min: u8,
}
