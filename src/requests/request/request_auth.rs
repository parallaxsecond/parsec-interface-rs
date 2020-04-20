// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::requests::Result;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use std::io::{Read, Write};

/// Wrapper around the authentication value of a request.
///
/// Hides the contents and keeps them immutable.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RequestAuth {
    bytes: Vec<u8>,
}

impl RequestAuth {
    /// Construct new, empty request authentication field.
    /// Available for testing only.
    #[cfg(feature = "testing")]
    pub(super) fn new() -> RequestAuth {
        RequestAuth { bytes: Vec::new() }
    }

    /// Read a request authentication field from the stream, given the length
    /// of the byte stream contained.
    pub(super) fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<RequestAuth> {
        let bytes = get_from_stream!(stream; len);
        Ok(RequestAuth { bytes })
    }

    /// Write request authentication field to stream.
    pub(super) fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.bytes)?;
        Ok(())
    }

    /// Create a `RequestAuth` from a vector of bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> RequestAuth {
        RequestAuth { bytes }
    }

    /// Get the auth as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size of the auth field.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if auth field is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
