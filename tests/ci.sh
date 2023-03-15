#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Continuous Integration test script, executed by GitHub Actions on x86 and
# Travis CI on Arm64.

# To update the `parsec-operations` submodule, rebase onto the latest release and commit before running `ci.sh`

set -euf -o pipefail

# The Parsec operations repository is included as a submodule. It is
# necessary to update it first.
git submodule update --init

##############
# Build test #
##############
RUST_BACKTRACE=1 cargo build
RUST_BACKTRACE=1 cargo build --features testing
RUST_BACKTRACE=1 cargo build --features regenerate-protobuf

#################
# Static checks #
#################
# On native target clippy or fmt might not be available.
if cargo fmt -h
then
	cargo fmt --all -- --check
fi
if cargo clippy -h
then
	cargo clippy --all-targets -- -D clippy::all -D clippy::cargo
fi

############################
# Unit tests and doc tests #
############################
RUST_BACKTRACE=1 cargo test --all-features

cargo clean
