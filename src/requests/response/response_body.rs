// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Wrapper around the body of a response.
///
/// Hides the contents and keeps them immutable.
#[derive(Debug, Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct ResponseBody {
    buffer: Vec<u8>,
}

impl Deref for ResponseBody {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for ResponseBody {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl ResponseBody {
    /// Create a new empty response body.
    pub(crate) fn new() -> ResponseBody {
        ResponseBody { buffer: Vec::new() }
    }

    /// Read a response body from a stream, given the number of bytes it contains.
    pub(super) fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<ResponseBody> {
        let buffer = get_from_stream!(stream; len);
        Ok(ResponseBody { buffer })
    }

    /// Write a response body to a stream.
    pub(super) fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.buffer)?;
        Ok(())
    }

    /// Create a `ResponseBody` from a vector of bytes.
    pub(crate) fn from_bytes(buffer: Vec<u8>) -> ResponseBody {
        ResponseBody { buffer }
    }

    /// Get the body as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the size of the body.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if body is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}
