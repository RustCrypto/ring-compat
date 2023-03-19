# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 (2023-03-19)
### Added
- `ed25518::SigningIey::from_bytes` ([#114])
- `ed25519::SigningKey::generate` ([#115])
- Impl `signature::Keypair` trait ([#116])

### Changed
- Bump elliptic curve dependencies; MSRV 1.65 ([#112])
  - `ecdsa` v0.16
  - `elliptic-curve` v0.13
  - `p256` v0.13
  - `p384` v0.13
  - `pkcs8` v0.10
- Rename `ed25519::SigningKey::from_seed` => `::from_slice` ([#114])
- Rename `ed25519::VerifyingKey::new` => `::from_slice` ([#114])

[#112]: https://github.com/RustCrypto/ring-compat/pull/112
[#114]: https://github.com/RustCrypto/ring-compat/pull/114
[#115]: https://github.com/RustCrypto/ring-compat/pull/115
[#116]: https://github.com/RustCrypto/ring-compat/pull/116

## 0.6.0 (2023-01-21)
### Changed
- Upgrade to `signature` v2-compatible dependencies ([#105])

[#105]: https://github.com/RustCrypto/ring-compat/pull/105

## 0.5.1 (2022-12-12)
### Added
- Re-export `ring` ([#102])

[#102]: https://github.com/RustCrypto/ring-compat/pull/102

## 0.5.0 (2022-12-11)
### Added
- Impl `pkcs8::DecodePrivateKey` for ECDSA and Ed25519 signing keys ([#99])

### Changed
- Bump `aead` dependency to v0.5 ([#86])
- Bump `digest` to v0.10 ([#94])
- Bump `p256` and `p384` to v0.11 ([#95])
- Use namespaced/weak features; MSRV 1.60 ([#97])
- Rename `verify_key` => `verifying_key` ([#98])

[#86]: https://github.com/RustCrypto/ring-compat/pull/86
[#94]: https://github.com/RustCrypto/ring-compat/pull/94
[#95]: https://github.com/RustCrypto/ring-compat/pull/95
[#97]: https://github.com/RustCrypto/ring-compat/pull/97
[#98]: https://github.com/RustCrypto/ring-compat/pull/98
[#99]: https://github.com/RustCrypto/ring-compat/pull/99

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
