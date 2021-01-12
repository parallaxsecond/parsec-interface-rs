// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]

use std::fs::read_dir;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

fn generate_proto_sources() -> Result<()> {
    let path = String::from("parsec-operations/protobuf");
    let dir_entries = read_dir(Path::new(&path))?;
    let files: Result<Vec<String>> = dir_entries
        .map(|protos_file| {
            protos_file?
                .path()
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "conversion from OsString to String failed",
                    )
                })
        })
        // Fail the entire operation if there was an error.
        .collect();
    let proto_files: Vec<String> = files?
        .into_iter()
        .filter(|string| string.ends_with(".proto"))
        .collect();
    let files_slices: Vec<&str> = proto_files.iter().map(|file| &file[..]).collect();
    prost_build::compile_protos(&files_slices, &[&path])
}

fn main() -> Result<()> {
    generate_proto_sources()
}
