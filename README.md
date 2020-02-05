<!--
  -- Copyright (c) 2019, Arm Limited, All Rights Reserved
  -- SPDX-License-Identifier: Apache-2.0
  --
  -- Licensed under the Apache License, Version 2.0 (the "License"); you may
  -- not use this file except in compliance with the License.
  -- You may obtain a copy of the License at
  --
  -- http://www.apache.org/licenses/LICENSE-2.0
  --
  -- Unless required by applicable law or agreed to in writing, software
  -- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  -- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  -- See the License for the specific language governing permissions and
  -- limitations under the License.
--->
# Parsec Rust Interface

![](https://github.com/parallaxsecond/parsec-interface-rs/workflows/Continuous%20Integration/badge.svg)
![](https://travis-ci.com/parallaxsecond/parsec.svg?branch=master)

This repository contains an interface library to be used both by the Parsec service and a Rust Client library.
The library contains methods to communicate using the [wire protocol](https://github.com/parallaxsecond/parsec/blob/master/docs/wire_protocol.md).

## Build

The Parsec operations repository is included as a submodule. Make sure to update it first before
trying to compile otherwise it will not work ("`No such file or directory`").

```bash
$ git submodule update --init
```

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

This project uses the following third party crates:
* serde (Apache-2.0)
* bincode (MIT)
* num-traits (MIT and Apache-2.0)
* num-derive (MIT and Apache-2.0)
* prost-build (Apache-2.0)
* prost (Apache-2.0)
* bytes (MIT)
* num (MIT and Apache-2.0)
* uuid (Apache-2.0)
* log (MIT and Apache-2.0)
* arbitrary (MIT and Apache-2.0)

## Contributing

Please check the [Contributing](CONTRIBUTING.md) to know more about the contribution process.

