// Copyright (c) 2019, Arm Limited, All Rights Reserved
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
use std::env;
use std::fs::read_dir;
use std::io::Result;
use std::path::Path;
use std::process::Command;

const PARSEC_OPERATIONS_VERSION: &str = "0.2.0";

fn generate_proto_sources() -> Result<()> {
    let path = format!(
        "{}/parsec-operations-{}/protobuf",
        env::var("OUT_DIR").unwrap(),
        PARSEC_OPERATIONS_VERSION
    );
    let dir_entries = read_dir(Path::new(&path))?;
    let files: Vec<String> = dir_entries
        .map(|protos_file| {
            protos_file
                .unwrap()
                .path()
                .into_os_string()
                .into_string()
                .unwrap()
        })
        .filter(|string| string.ends_with(".proto"))
        .collect();
    let files_slices: Vec<&str> = files.iter().map(|file| &file[..]).collect();
    prost_build::compile_protos(&files_slices, &[&path]).expect("failed to generate protos");

    Ok(())
}

fn get_protobuf_files() {
    // TODO: Use semantic versioning to get the newest versions.
    if !Command::new("wget")
        .arg(format!(
            "https://github.com/parallaxsecond/parsec-operations/archive/{}.tar.gz",
            PARSEC_OPERATIONS_VERSION
        ))
        .arg(format!(
            "--directory-prefix={}",
            env::var("OUT_DIR").unwrap()
        ))
        .status()
        .expect("wget command failed.")
        .success()
    {
        panic!("wget command returned an error status.");
    }

    // Gets extracted as parsec-operations-PARSEC_OPERATIONS_VERSION directory.
    if !Command::new("tar")
        .arg("xf")
        .arg(format!(
            "{}/{}.tar.gz",
            env::var("OUT_DIR").unwrap(),
            PARSEC_OPERATIONS_VERSION
        ))
        .arg("--directory")
        .arg(env::var("OUT_DIR").unwrap())
        .status()
        .expect("tar command failed.")
        .success()
    {
        panic!("tar command returned an error status.");
    }
}

fn main() {
    get_protobuf_files();
    generate_proto_sources().expect("Failed to generate protobuf source code from proto files.");
}
