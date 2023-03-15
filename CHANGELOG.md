# Changelog

## [0.28.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.28.0) (2023-03-13)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.27.0...0.28.0)

**Merged pull requests:**

- Fix CI issues [\#136](https://github.com/parallaxsecond/parsec-interface-rs/pull/136) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Do not derive Arbitrary for types not implementing it [\#135](https://github.com/parallaxsecond/parsec-interface-rs/pull/135) ([ema](https://github.com/ema))
- Update to remove const\_err [\#134](https://github.com/parallaxsecond/parsec-interface-rs/pull/134) ([marcsvll](https://github.com/marcsvll))

## [0.27.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.27.0) (2022-09-09)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.26.0...0.27.0)

**Implemented enhancements:**

- Strongify wire header serialization [\#115](https://github.com/parallaxsecond/parsec-interface-rs/issues/115)
- Validate hash length for psa\_sign\_hash [\#107](https://github.com/parallaxsecond/parsec-interface-rs/issues/107)
- Find a way to represent deprecated primitives [\#33](https://github.com/parallaxsecond/parsec-interface-rs/issues/33)

**Merged pull requests:**

- Release prep 0.27.0 [\#132](https://github.com/parallaxsecond/parsec-interface-rs/pull/132) ([mohamedasaker-arm](https://github.com/mohamedasaker-arm))
- Use psa-crypto with updated zeroize [\#131](https://github.com/parallaxsecond/parsec-interface-rs/pull/131) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Fix clippy warnings and ignore those under generated ops [\#130](https://github.com/parallaxsecond/parsec-interface-rs/pull/130) ([mohamedasaker-arm](https://github.com/mohamedasaker-arm))
- Feature/33 represent check deprecated primitives [\#129](https://github.com/parallaxsecond/parsec-interface-rs/pull/129) ([mohamedasaker-arm](https://github.com/mohamedasaker-arm))
- Configure bincode used in wire header serialization/deserialization  [\#128](https://github.com/parallaxsecond/parsec-interface-rs/pull/128) ([mohamedasaker-arm](https://github.com/mohamedasaker-arm))

## [0.26.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.26.0) (2022-02-15)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.25.0...0.26.0)

**Implemented enhancements:**

- Add key attestation operations [\#124](https://github.com/parallaxsecond/parsec-interface-rs/pull/124) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Prepare for 0.26.0 release [\#126](https://github.com/parallaxsecond/parsec-interface-rs/pull/126) ([ionut-arm](https://github.com/ionut-arm))
- Merge can-do-crypto branch into main [\#125](https://github.com/parallaxsecond/parsec-interface-rs/pull/125) ([anta5010](https://github.com/anta5010))
- Merge origin/main into can-do-crypto  [\#123](https://github.com/parallaxsecond/parsec-interface-rs/pull/123) ([anta5010](https://github.com/anta5010))
- Add PsaCipherEncrypt and PsaCipherDecrypt operations [\#122](https://github.com/parallaxsecond/parsec-interface-rs/pull/122) ([akazimierskigl](https://github.com/akazimierskigl))
- Upgrade prost to 0.8.0 [\#121](https://github.com/parallaxsecond/parsec-interface-rs/pull/121) ([hug-dev](https://github.com/hug-dev))
- Added the changes required for the CanDoCrypto operation. [\#120](https://github.com/parallaxsecond/parsec-interface-rs/pull/120) ([Kakemone](https://github.com/Kakemone))
- Update CHANGELOG [\#119](https://github.com/parallaxsecond/parsec-interface-rs/pull/119) ([hug-dev](https://github.com/hug-dev))

## [0.25.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.25.0) (2021-08-03)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.24.0...0.25.0)

**Implemented enhancements:**

- Investigate pre-generating Rust protobuf code [\#98](https://github.com/parallaxsecond/parsec-interface-rs/issues/98)
- Implement Deref on RequestBody and ResponseBody [\#61](https://github.com/parallaxsecond/parsec-interface-rs/issues/61)

**Fixed bugs:**

- Check that reserved fields are zero [\#109](https://github.com/parallaxsecond/parsec-interface-rs/pull/109) ([hug-dev](https://github.com/hug-dev))

**Security fixes:**

- Bump prost crate versions [\#112](https://github.com/parallaxsecond/parsec-interface-rs/pull/112) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Prepare for next release [\#118](https://github.com/parallaxsecond/parsec-interface-rs/pull/118) ([hug-dev](https://github.com/hug-dev))
- Commit the generated Rust protobuf files in tree [\#117](https://github.com/parallaxsecond/parsec-interface-rs/pull/117) ([hug-dev](https://github.com/hug-dev))
- Implement Deref\(Mut\) on bodies [\#116](https://github.com/parallaxsecond/parsec-interface-rs/pull/116) ([hug-dev](https://github.com/hug-dev))
- Add a cargo audit config [\#114](https://github.com/parallaxsecond/parsec-interface-rs/pull/114) ([hug-dev](https://github.com/hug-dev))
- Revert "Bump prost crate versions" [\#113](https://github.com/parallaxsecond/parsec-interface-rs/pull/113) ([ionut-arm](https://github.com/ionut-arm))
- Update psa-crypto [\#110](https://github.com/parallaxsecond/parsec-interface-rs/pull/110) ([hug-dev](https://github.com/hug-dev))
- Add more precision to error messages [\#108](https://github.com/parallaxsecond/parsec-interface-rs/pull/108) ([hug-dev](https://github.com/hug-dev))
- Fix latest clippy lints [\#106](https://github.com/parallaxsecond/parsec-interface-rs/pull/106) ([hug-dev](https://github.com/hug-dev))
- Add PsaSignMessage and PsaVerifyMessage operations [\#105](https://github.com/parallaxsecond/parsec-interface-rs/pull/105) ([akazimierskigl](https://github.com/akazimierskigl))
- Add updated changelog [\#104](https://github.com/parallaxsecond/parsec-interface-rs/pull/104) ([hug-dev](https://github.com/hug-dev))

## [0.24.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.24.0) (2021-03-18)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.23.0...0.24.0)

**Implemented enhancements:**

- Rename ProviderID [\#36](https://github.com/parallaxsecond/parsec-interface-rs/issues/36)
- Investigate possible use of zerocopy [\#10](https://github.com/parallaxsecond/parsec-interface-rs/issues/10)

**Merged pull requests:**

- Add version 0.24.0 [\#103](https://github.com/parallaxsecond/parsec-interface-rs/pull/103) ([hug-dev](https://github.com/hug-dev))
- Update psa-crypto dependence [\#102](https://github.com/parallaxsecond/parsec-interface-rs/pull/102) ([hug-dev](https://github.com/hug-dev))
- Implement Display on ProviderID and AuthType [\#101](https://github.com/parallaxsecond/parsec-interface-rs/pull/101) ([hug-dev](https://github.com/hug-dev))
- Add log message to help debugging [\#100](https://github.com/parallaxsecond/parsec-interface-rs/pull/100) ([hug-dev](https://github.com/hug-dev))
- Use newest PSA Crypto crate version [\#99](https://github.com/parallaxsecond/parsec-interface-rs/pull/99) ([ionut-arm](https://github.com/ionut-arm))
- Add Changelog file [\#97](https://github.com/parallaxsecond/parsec-interface-rs/pull/97) ([ionut-arm](https://github.com/ionut-arm))

## [0.23.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.23.0) (2021-01-19)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.22.0...0.23.0)

**Security fixes:**

- Add a new ResponseStatus for admin operations [\#93](https://github.com/parallaxsecond/parsec-interface-rs/issues/93)

**Closed issues:**

- Add ListClients and DeleteClient structures [\#94](https://github.com/parallaxsecond/parsec-interface-rs/issues/94)

**Merged pull requests:**

- Bump PSA Crypto version [\#96](https://github.com/parallaxsecond/parsec-interface-rs/pull/96) ([ionut-arm](https://github.com/ionut-arm))
- Add ListClients and DeleteClient operations [\#95](https://github.com/parallaxsecond/parsec-interface-rs/pull/95) ([hug-dev](https://github.com/hug-dev))
- Fix lints and remove Travis build [\#92](https://github.com/parallaxsecond/parsec-interface-rs/pull/92) ([ionut-arm](https://github.com/ionut-arm))

## [0.22.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.22.0) (2020-12-18)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.21.0...0.22.0)

**Merged pull requests:**

- Consume psa-crypto at version 0.6.1 and bump interface to 0.22.0 [\#91](https://github.com/parallaxsecond/parsec-interface-rs/pull/91) ([paulhowardarm](https://github.com/paulhowardarm))
- Add CryptoAuthLib to Provider enumeration. [\#90](https://github.com/parallaxsecond/parsec-interface-rs/pull/90) ([RobertDrazkowskiGL](https://github.com/RobertDrazkowskiGL))
- Update psa-crypto version [\#89](https://github.com/parallaxsecond/parsec-interface-rs/pull/89) ([hug-dev](https://github.com/hug-dev))

## [0.21.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.21.0) (2020-10-20)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.20.2...0.21.0)

**Implemented enhancements:**

- Write opcode numbers in hexadecimal format [\#82](https://github.com/parallaxsecond/parsec-interface-rs/issues/82)
- Create conversion method from TryFromIntError for ResponseStatus [\#53](https://github.com/parallaxsecond/parsec-interface-rs/issues/53)
- Add Trusted Services crypto provider ID [\#87](https://github.com/parallaxsecond/parsec-interface-rs/pull/87) ([ionut-arm](https://github.com/ionut-arm))
- Add a JWT SVID authentication type [\#84](https://github.com/parallaxsecond/parsec-interface-rs/pull/84) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Fix nightly CI [\#78](https://github.com/parallaxsecond/parsec-interface-rs/pull/78) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Add support for another authenticator [\#70](https://github.com/parallaxsecond/parsec-interface-rs/issues/70)

**Merged pull requests:**

- Add methods to check opcode nature [\#88](https://github.com/parallaxsecond/parsec-interface-rs/pull/88) ([hug-dev](https://github.com/hug-dev))
- Use hexadecimal format for opcode values [\#86](https://github.com/parallaxsecond/parsec-interface-rs/pull/86) ([hug-dev](https://github.com/hug-dev))
- Add a uuid::Error conversion [\#85](https://github.com/parallaxsecond/parsec-interface-rs/pull/85) ([hug-dev](https://github.com/hug-dev))
- Add ListKeys operation [\#83](https://github.com/parallaxsecond/parsec-interface-rs/pull/83) ([joechrisellis](https://github.com/joechrisellis))

## [0.20.2](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.20.2) (2020-09-04)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.20.1...0.20.2)

**Implemented enhancements:**

- Re-export `uuid` crate [\#51](https://github.com/parallaxsecond/parsec-interface-rs/issues/51)
- Upgrade dependencies [\#77](https://github.com/parallaxsecond/parsec-interface-rs/pull/77) ([hug-dev](https://github.com/hug-dev))

**Security fixes:**

- Audit response status code for information disclosure [\#59](https://github.com/parallaxsecond/parsec-interface-rs/issues/59)

## [0.20.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.20.1) (2020-08-20)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.20.0...0.20.1)

## [0.20.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.20.0) (2020-08-14)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.19.0...0.20.0)

**Fixed bugs:**

- Fix clippy warnings [\#67](https://github.com/parallaxsecond/parsec-interface-rs/pull/67) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Added raw key agreement interface [\#75](https://github.com/parallaxsecond/parsec-interface-rs/pull/75) ([sbailey-arm](https://github.com/sbailey-arm))
- Added hash compute and compare interfaces [\#74](https://github.com/parallaxsecond/parsec-interface-rs/pull/74) ([sbailey-arm](https://github.com/sbailey-arm))
- Added aead encrypt and decrypt [\#73](https://github.com/parallaxsecond/parsec-interface-rs/pull/73) ([sbailey-arm](https://github.com/sbailey-arm))
- Add support for ListAuthenticators operation [\#72](https://github.com/parallaxsecond/parsec-interface-rs/pull/72) ([joechrisellis](https://github.com/joechrisellis))
- Add new AuthType variants [\#71](https://github.com/parallaxsecond/parsec-interface-rs/pull/71) ([joechrisellis](https://github.com/joechrisellis))
- Add support for `psa_generate_random` [\#68](https://github.com/parallaxsecond/parsec-interface-rs/pull/68) ([joechrisellis](https://github.com/joechrisellis))

## [0.19.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.19.0) (2020-07-15)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.18.0...0.19.0)

**Implemented enhancements:**

- Bump version of psa-crypto to 0.3.0 [\#66](https://github.com/parallaxsecond/parsec-interface-rs/pull/66) ([hug-dev](https://github.com/hug-dev))
- Added export key [\#65](https://github.com/parallaxsecond/parsec-interface-rs/pull/65) ([sbailey-arm](https://github.com/sbailey-arm))

**Merged pull requests:**

- Added the from impls for going from an operations and result to NativeOperation and NativeResult for asym encrypt and decrypt [\#64](https://github.com/parallaxsecond/parsec-interface-rs/pull/64) ([sbailey-arm](https://github.com/sbailey-arm))

## [0.18.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.18.0) (2020-07-07)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.17.1...0.18.0)

**Merged pull requests:**

- Added asymmetric encrypt and decrypt [\#63](https://github.com/parallaxsecond/parsec-interface-rs/pull/63) ([sbailey-arm](https://github.com/sbailey-arm))

## [0.17.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.17.1) (2020-07-01)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.17.0...0.17.1)

**Fixed bugs:**

- Fix compilation on testing feature [\#62](https://github.com/parallaxsecond/parsec-interface-rs/pull/62) ([hug-dev](https://github.com/hug-dev))

## [0.17.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.17.0) (2020-06-26)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.16.0...0.17.0)

**Implemented enhancements:**

- Implement DataBuffer and replace byte vectors [\#60](https://github.com/parallaxsecond/parsec-interface-rs/pull/60) ([ionut-arm](https://github.com/ionut-arm))

## [0.16.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.16.0) (2020-06-18)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.15.0...0.16.0)

**Implemented enhancements:**

- Import the newer version of psa-crypto [\#58](https://github.com/parallaxsecond/parsec-interface-rs/pull/58) ([hug-dev](https://github.com/hug-dev))

## [0.15.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.15.0) (2020-06-03)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.14.1...0.15.0)

**Implemented enhancements:**

- Use crates.io for psa-crypto [\#57](https://github.com/parallaxsecond/parsec-interface-rs/pull/57) ([hug-dev](https://github.com/hug-dev))
- Derive PartialEq, Hash and Eq on ProviderInfo [\#54](https://github.com/parallaxsecond/parsec-interface-rs/pull/54) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Replace algorithms and attributes with psa-crypto [\#55](https://github.com/parallaxsecond/parsec-interface-rs/pull/55) ([ionut-arm](https://github.com/ionut-arm))

## [0.14.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.14.1) (2020-05-11)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.14.0...0.14.1)

**Implemented enhancements:**

- Add validation to sign and verify operations [\#52](https://github.com/parallaxsecond/parsec-interface-rs/pull/52) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Modify Opcode enumeration size [\#49](https://github.com/parallaxsecond/parsec-interface-rs/issues/49)
- Modify Opcode size [\#50](https://github.com/parallaxsecond/parsec-interface-rs/pull/50) ([hug-dev](https://github.com/hug-dev))

## [0.14.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.14.0) (2020-04-23)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.13.0...0.14.0)

**Implemented enhancements:**

- Breaking change to wire protocol 1.0 to support additional fields and transports [\#48](https://github.com/parallaxsecond/parsec-interface-rs/pull/48) ([paulhowardarm](https://github.com/paulhowardarm))
- Update copyrights on all files [\#46](https://github.com/parallaxsecond/parsec-interface-rs/pull/46) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Make wire protocol version a property of request and response headers [\#41](https://github.com/parallaxsecond/parsec-interface-rs/issues/41)
- Make sure there is a clear separation between PSA and Core structures [\#30](https://github.com/parallaxsecond/parsec-interface-rs/issues/30)

## [0.13.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.13.0) (2020-04-15)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.12.0...0.13.0)

**Implemented enhancements:**

- Add body type getter in Convert trait [\#40](https://github.com/parallaxsecond/parsec-interface-rs/issues/40)
- Add provider ID to list\_opcodes [\#44](https://github.com/parallaxsecond/parsec-interface-rs/pull/44) ([ionut-arm](https://github.com/ionut-arm))
- Add body\_type fn to Convert [\#42](https://github.com/parallaxsecond/parsec-interface-rs/pull/42) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Bump version number [\#45](https://github.com/parallaxsecond/parsec-interface-rs/pull/45) ([ionut-arm](https://github.com/ionut-arm))

## [0.12.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.12.0) (2020-04-07)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.11.0...0.12.0)

**Implemented enhancements:**

- Add faillible methods [\#39](https://github.com/parallaxsecond/parsec-interface-rs/pull/39) ([hug-dev](https://github.com/hug-dev))
- Add a new method for permisison and compatibility [\#38](https://github.com/parallaxsecond/parsec-interface-rs/pull/38) ([hug-dev](https://github.com/hug-dev))

## [0.11.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.11.0) (2020-04-03)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.10.0...0.11.0)

**Implemented enhancements:**

- Add permits method to check for policy [\#37](https://github.com/parallaxsecond/parsec-interface-rs/pull/37) ([hug-dev](https://github.com/hug-dev))

## [0.10.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.10.0) (2020-03-18)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.8.3...0.10.0)

**Implemented enhancements:**

- Update to PSA Crypto API 1.0.0 [\#4](https://github.com/parallaxsecond/parsec-interface-rs/issues/4)
- Update to PSA Crypto API 1.0.0 [\#28](https://github.com/parallaxsecond/parsec-interface-rs/pull/28) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Update documentation after upgrading to PSA Crypto 1.0.0 [\#29](https://github.com/parallaxsecond/parsec-interface-rs/issues/29)

**Merged pull requests:**

- Add missing\_doc as an error [\#31](https://github.com/parallaxsecond/parsec-interface-rs/pull/31) ([hug-dev](https://github.com/hug-dev))

## [0.8.3](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.8.3) (2020-02-28)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.8.2...0.8.3)

**Implemented enhancements:**

- Add code documentation [\#26](https://github.com/parallaxsecond/parsec-interface-rs/pull/26) ([hug-dev](https://github.com/hug-dev))

## [0.8.2](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.8.2) (2020-02-25)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.8.1...0.8.2)

## [0.8.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.8.1) (2020-02-24)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.8.0...0.8.1)

**Fixed bugs:**

- Fix supported wire protocol version [\#24](https://github.com/parallaxsecond/parsec-interface-rs/pull/24) ([hug-dev](https://github.com/hug-dev))

## [0.8.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.8.0) (2020-02-21)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.7.1...0.8.0)

## [0.7.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.7.1) (2020-02-06)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.7.0...0.7.1)

**Implemented enhancements:**

- Add a submodule for the operations [\#21](https://github.com/parallaxsecond/parsec-interface-rs/pull/21) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Deploy on crates.io [\#14](https://github.com/parallaxsecond/parsec-interface-rs/issues/14)

## [0.7.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.7.0) (2020-02-05)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.6.1...0.7.0)

**Implemented enhancements:**

- Add Travis CI tests for Aarch64 [\#12](https://github.com/parallaxsecond/parsec-interface-rs/issues/12)

**Fixed bugs:**

- Build fails with confusing message if wget is not available [\#17](https://github.com/parallaxsecond/parsec-interface-rs/issues/17)
- Replace direct `Command` by crates in the build script [\#7](https://github.com/parallaxsecond/parsec-interface-rs/issues/7)

## [0.6.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.6.1) (2020-02-04)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.6.0...0.6.1)

**Implemented enhancements:**

- Various lint fixes [\#18](https://github.com/parallaxsecond/parsec-interface-rs/pull/18) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Replace cross tests for native tests [\#19](https://github.com/parallaxsecond/parsec-interface-rs/pull/19) ([hug-dev](https://github.com/hug-dev))

## [0.6.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.6.0) (2020-01-30)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.5.1...0.6.0)

**Fixed bugs:**

- Add body length limit to reading requests and responses [\#16](https://github.com/parallaxsecond/parsec-interface-rs/pull/16) ([ionut-arm](https://github.com/ionut-arm))

## [0.5.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.5.1) (2020-01-28)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.5.0...0.5.1)

**Implemented enhancements:**

- Derive Arbitrary for fuzz testing [\#15](https://github.com/parallaxsecond/parsec-interface-rs/pull/15) ([ionut-arm](https://github.com/ionut-arm))

## [0.5.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.5.0) (2020-01-27)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.4.1...0.5.0)

**Implemented enhancements:**

- Remove most panicking behaviour [\#13](https://github.com/parallaxsecond/parsec-interface-rs/pull/13) ([hug-dev](https://github.com/hug-dev))

## [0.4.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.4.1) (2020-01-09)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.4.0...0.4.1)

**Implemented enhancements:**

- Deny compilation for some rustc lints [\#11](https://github.com/parallaxsecond/parsec-interface-rs/pull/11) ([hug-dev](https://github.com/hug-dev))

## [0.4.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.4.0) (2019-12-05)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.3.0...0.4.0)

**Implemented enhancements:**

- Add TPM Provider [\#9](https://github.com/parallaxsecond/parsec-interface-rs/pull/9) ([hug-dev](https://github.com/hug-dev))

## [0.3.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.3.0) (2019-11-18)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.2.1...0.3.0)

**Implemented enhancements:**

- Add PKCS 11 ProviderID enumeration variant [\#8](https://github.com/parallaxsecond/parsec-interface-rs/pull/8) ([hug-dev](https://github.com/hug-dev))

## [0.2.1](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.2.1) (2019-11-01)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.2.0...0.2.1)

**Implemented enhancements:**

- Add cross-compilation and testing to Arm64 on CI [\#6](https://github.com/parallaxsecond/parsec-interface-rs/pull/6) ([hug-dev](https://github.com/hug-dev))

## [0.2.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.2.0) (2019-10-23)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/0.1.0...0.2.0)

**Merged pull requests:**

- Remove references to key lifetime [\#5](https://github.com/parallaxsecond/parsec-interface-rs/pull/5) ([hug-dev](https://github.com/hug-dev))
- Remove ci folder and modify CI workflow [\#3](https://github.com/parallaxsecond/parsec-interface-rs/pull/3) ([hug-dev](https://github.com/hug-dev))

## [0.1.0](https://github.com/parallaxsecond/parsec-interface-rs/tree/0.1.0) (2019-10-09)

[Full Changelog](https://github.com/parallaxsecond/parsec-interface-rs/compare/c89c06232024d57d96826b41ea4d409a021fd530...0.1.0)

**Merged pull requests:**

- Add a specific tag when getting operations [\#2](https://github.com/parallaxsecond/parsec-interface-rs/pull/2) ([hug-dev](https://github.com/hug-dev))
- Split Rust interface into its own repository [\#1](https://github.com/parallaxsecond/parsec-interface-rs/pull/1) ([hug-dev](https://github.com/hug-dev))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
