# Parsec Rust Interface

<p align="center">
  <a href="https://crates.io/crates/parsec-interface"><img alt="Crates.io" src="https://img.shields.io/crates/v/parsec-interface"></a>
  <a href="https://docs.rs/parsec-interface"><img src="https://docs.rs/parsec-interface/badge.svg" alt="Code documentation"/></a>
</p>

This repository contains an interface library to be used both by the Parsec service and a Rust Client library.
The library contains methods to communicate using the [wire protocol](https://parallaxsecond.github.io/parsec-book/parsec_client/wire_protocol.html).

## Build

The Parsec operations repository is included as a submodule. Make sure to update it first before
trying to compile otherwise it will not work ("`No such file or directory`").

```bash
$ git submodule update --init
```

By default, the crate will use the pre-generated Rust Protobuf files in
`src/operations_protobuf/generated_ops`. To re-generate them from the `parsec-operations`
submodule, compile this
crate with the feature `regenerate-protobuf`.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

## Contributing

Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing/index.html)
to know more about the contribution process.

*Copyright 2021 Contributors to the Parsec project.*
