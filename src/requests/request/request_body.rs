// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::requests::Result;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use std::io::{Read, Write};
use zeroize::Zeroize;

/// Wrapper around the body of a request.
///
/// Hides the contents and keeps them immutable.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct RequestBody {
    buffer: Vec<u8>,
}

impl RequestBody {
    /// Create a new, emtpy request body field.
    /// Available for testing only.
    #[cfg(feature = "testing")]
    pub(super) fn new() -> RequestBody {
        RequestBody { bytes: Vec::new() }
    }

    /// Read the request body from a stream, given the length of the content.
    pub(super) fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<RequestBody> {
        let buffer = get_from_stream!(stream; len);
        Ok(RequestBody { buffer })
    }

    /// Write the request body to a stream.
    pub(super) fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.buffer)?;
        Ok(())
    }

    /// Create a `RequestBody` from a vector of bytes.
    pub(crate) fn from_bytes(buffer: Vec<u8>) -> RequestBody {
        RequestBody { buffer }
    }

    /// Get the body as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Get size of body.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if body is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Create a `RequestBody` from the provided bytes.
    ///
    /// Must only be used for testing purposes.
    #[cfg(feature = "testing")]
    pub fn _from_bytes(bytes: Vec<u8>) -> RequestBody {
        RequestBody { bytes }
    }
}
