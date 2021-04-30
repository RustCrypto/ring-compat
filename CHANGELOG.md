# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.1 (2021-04-30)
### Changed
- Rename `VerifyKey` => `VerifyingKey` ([#38])

[#38]: https://github.com/RustCrypto/ring-compat/pull/38

## 0.2.0 (2021-04-30) [YANKED]
### Added
- `std` feature that enables `digest/std` ([#33])

### Changed
- Bump `aead` to v0.4 ([#34])
- Bump `ecdsa` to v0.11 ([#34])
- Bump `p256` to v0.8 ([#34])
- Bump `p384` to v0.7 ([#34])

[#33]: https://github.com/RustCrypto/ring-compat/pull/33
[#34]: https://github.com/RustCrypto/ring-compat/pull/34

## 0.1.1 (2020-12-11)
### Added
- `ecdsa::VerifyKey::as_bytes()` function ([#21])

[#21]: https://github.com/RustCrypto/ring-compat/pull/21

## 0.1.0 (2020-10-09)
### Added
- Signature support: ECDSA and Ed25519 ([#17])

### Changed
- Factor apart `aead` and `digest` modules ([#14], [#15])

[#17]: https://github.com/RustCrypto/ring-compat/pull/17
[#15]: https://github.com/RustCrypto/ring-compat/pull/15
[#14]: https://github.com/RustCrypto/ring-compat/pull/14

## 0.0.1 (2020-10-08)
- Initial release
