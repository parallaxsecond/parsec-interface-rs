// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::requests::Result;
use crate::secrecy::{ExposeSecret, Secret};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use std::io::{Read, Write};

/// Wrapper around the authentication value of a request.
///
/// Hides the contents and keeps them immutable.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[allow(missing_debug_implementations)]
pub struct RequestAuth {
    /// Buffer holding the authentication token as a byte vector
    pub buffer: Secret<Vec<u8>>,
}

impl RequestAuth {
    /// Create a new authentication field for a request.
    pub fn new(bytes: Vec<u8>) -> Self {
        RequestAuth {
            buffer: Secret::new(bytes),
        }
    }

    /// Read a request authentication field from the stream, given the length
    /// of the byte stream contained.
    pub(super) fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<RequestAuth> {
        let buffer = get_from_stream!(stream; len);
        Ok(RequestAuth {
            buffer: Secret::new(buffer),
        })
    }

    /// Write request authentication field to stream.
    pub(super) fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(self.buffer.expose_secret())?;
        Ok(())
    }
}
