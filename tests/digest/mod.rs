//! Digest tests

// TODO(tarcieri): fix commented out tests

use digest::{core_api::BlockSizeUser, generic_array::typenum::Unsigned, OutputSizeUser};
use ring_compat::digest::*;

// new_test!(sha1_main, "sha1", Sha1, digest_test);
// new_test!(sha256_main, "sha256", Sha256, digest_test);
// new_test!(sha384_main, "sha384", Sha384, digest_test);
// new_test!(sha512_main, "sha512", Sha512, digest_test);
// new_test!(sha512_256_main, "sha512_256", Sha512Trunc256, digest_test);

// #[test]
// fn sha1_1million_a() {
//     let output = include_bytes!("data/one_million_a.bin");
//     one_million_a::<Sha1>(output);
// }

// #[test]
// fn sha256_1million_a() {
//     let output = include_bytes!("data/sha256_one_million_a.bin");
//     one_million_a::<Sha256>(output);
// }

// #[test]
// fn sha512_1million_a() {
//     let output = include_bytes!("data/sha512_one_million_a.bin");
//     one_million_a::<Sha512>(output);
// }

#[test]
fn test_block_len() {
    assert_eq!(
        ring::digest::SHA1_FOR_LEGACY_USE_ONLY.block_len,
        <Sha1 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA256.block_len,
        <Sha256 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA384.block_len,
        <Sha384 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512.block_len,
        <Sha512 as BlockSizeUser>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512_256.block_len,
        <Sha512Trunc256 as BlockSizeUser>::BlockSize::to_usize()
    );
}

#[test]
fn test_output_len() {
    assert_eq!(
        ring::digest::SHA1_FOR_LEGACY_USE_ONLY.output_len,
        <Sha1 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA256.output_len,
        <Sha256 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA384.output_len,
        <Sha384 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512.output_len,
        <Sha512 as OutputSizeUser>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512_256.output_len,
        <Sha512Trunc256 as OutputSizeUser>::OutputSize::to_usize()
    );
}
