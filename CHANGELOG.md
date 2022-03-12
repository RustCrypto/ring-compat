# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.1 (2022-03-12)
### Added
- Re-export `ring` ([#80])

### Changed
- Reuse AEAD cipher instance ([#79])

[#79]: https://github.com/RustCrypto/ring-compat/pull/79
[#80]: https://github.com/RustCrypto/ring-compat/pull/80

## 0.4.0 (2021-12-15)
### Changed
- Bump `ecdsa` to v0.13 ([#65])
- Bump `p256` to v0.10 ([#65])
- Bump `p384` to v0.9 ([#65])
- Rust 2021 edition upgrade ([#66])

[#65]: https://github.com/RustCrypto/ring-compat/pull/65
[#66]: https://github.com/RustCrypto/ring-compat/pull/66

## 0.3.2 (2021-09-14)
- Republishing with identical code to v0.3.1 to update the crates.io description.

## 0.3.1 (2021-06-08)
### Changed
- Bump `ecdsa` to v0.12 ([#45])
- Bump `p256` to v0.9 ([#45])
- Bump `p384` to v0.8 ([#45])
- MSRV 1.51+ ([#45])

[#45]: https://github.com/RustCrypto/ring-compat/pull/45

## 0.3.0 [SKIPPED]

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
