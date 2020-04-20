// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Wrapper around the body of a response.
///
/// Hides the contents and keeps them immutable.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ResponseBody {
    bytes: Vec<u8>,
}

impl ResponseBody {
    /// Create a new empty response body.
    pub(crate) fn new() -> ResponseBody {
        ResponseBody { bytes: Vec::new() }
    }

    /// Read a response body from a stream, given the number of bytes it contains.
    pub(super) fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<ResponseBody> {
        let bytes = get_from_stream!(stream; len);
        Ok(ResponseBody { bytes })
    }

    /// Write a response body to a stream.
    pub(super) fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.bytes)?;
        Ok(())
    }

    /// Create a `ResponseBody` from a vector of bytes.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> ResponseBody {
        ResponseBody { bytes }
    }

    /// Get the body as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size of the body.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if body is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
