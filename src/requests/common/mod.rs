// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! This module implements the raw wire protocol header frame for requests and responses in
//! all defined versions of the protocol (currently just 1.0).
pub mod wire_header_1_0;

const MAGIC_NUMBER: u32 = 0x5EC0_A710;
