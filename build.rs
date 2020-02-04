// Copyright (c) 2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use curl::easy::Easy;
use flate2::read::GzDecoder;
use std::env;
use std::fs::{read_dir, File};
use std::io::{Error, ErrorKind, Result, Write};
use std::path::Path;
use tar::Archive;

const PARSEC_OPERATIONS_VERSION: &str = "0.2.0";

fn generate_proto_sources() -> Result<()> {
    let path = format!(
        "{}/parsec-operations-{}/protobuf",
        env::var("OUT_DIR").unwrap(),
        PARSEC_OPERATIONS_VERSION
    );
    let dir_entries = read_dir(Path::new(&path))?;
    let files: Result<Vec<String>> = dir_entries
        .map(|protos_file| {
            protos_file?
                .path()
                .into_os_string()
                .into_string()
                .or_else(|_| {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "conversion from OsString to String failed",
                    ))
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

fn get_protobuf_files() -> Result<()> {
    // TODO: Use semantic versioning to get the newest versions.
    let protobuf_archive_url = format!(
        "https://codeload.github.com/parallaxsecond/parsec-operations/tar.gz/{}",
        PARSEC_OPERATIONS_VERSION
    );
    let out_dir = env::var("OUT_DIR").unwrap();
    let protobuf_archive_path = format!("{}/{}.tar.gz", out_dir, PARSEC_OPERATIONS_VERSION);
    let mut protobuf_archive = File::create(&protobuf_archive_path)?;

    let mut buf = Vec::new();
    let mut handle = Easy::new();
    handle.url(&protobuf_archive_url)?;
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|data| {
            buf.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }

    protobuf_archive.write_all(&buf)?;

    // Drop and open the archive again so that GzDecoder sees it as a new file.
    let protobuf_archive = File::open(&protobuf_archive_path)?;

    let tar = GzDecoder::new(protobuf_archive);
    let mut archive = Archive::new(tar);
    archive.unpack(&out_dir)?;

    Ok(())
}

fn main() -> Result<()> {
    get_protobuf_files()?;
    generate_proto_sources()
}
