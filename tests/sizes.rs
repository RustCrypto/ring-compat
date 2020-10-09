use digest::generic_array::typenum::Unsigned;
use digest::{BlockInput, FixedOutput};
use ring_compat::digest::*;

#[test]
fn test_block_len() {
    assert_eq!(
        ring::digest::SHA1_FOR_LEGACY_USE_ONLY.block_len,
        <Sha1 as BlockInput>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA256.block_len,
        <Sha256 as BlockInput>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA384.block_len,
        <Sha384 as BlockInput>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512.block_len,
        <Sha512 as BlockInput>::BlockSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512_256.block_len,
        <Sha512Trunc256 as BlockInput>::BlockSize::to_usize()
    );
}

#[test]
fn test_output_len() {
    assert_eq!(
        ring::digest::SHA1_FOR_LEGACY_USE_ONLY.output_len,
        <Sha1 as FixedOutput>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA256.output_len,
        <Sha256 as FixedOutput>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA384.output_len,
        <Sha384 as FixedOutput>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512.output_len,
        <Sha512 as FixedOutput>::OutputSize::to_usize()
    );
    assert_eq!(
        ring::digest::SHA512_256.output_len,
        <Sha512Trunc256 as FixedOutput>::OutputSize::to_usize()
    );
}
