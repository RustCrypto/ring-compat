//! Digest algorithms: SHA-1, SHA-256, SHA-384, SHA-512

use core::mem;
use digest::{
    core_api::BlockSizeUser,
    generic_array::{typenum::*, GenericArray},
    FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update,
};
use ring::digest::Context;

macro_rules! impl_digest {
    (
        $(#[doc = $doc:tt])*
        $name:ident, $hasher:ident, $block_len:ty, $output_size:ty
    ) => {
        $(#[doc = $doc])*
        #[repr(transparent)]
        #[derive(Clone)]
        pub struct $name(Context);

        impl $name {
            fn take(&mut self) -> Context {
                mem::replace(&mut self.0, Context::new(&ring::digest::$hasher))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name(Context::new(&ring::digest::$hasher))
            }
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                self.0.update(data.as_ref())
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = $block_len;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
                *out = GenericArray::clone_from_slice(self.0.finish().as_ref());
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
                *out = GenericArray::clone_from_slice(self.take().finish().as_ref());
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                self.take();
            }
        }

        opaque_debug::implement!($name);
    };
}

impl_digest!(
    /// Structure representing the state of a SHA-1 computation
    Sha1,
    SHA1_FOR_LEGACY_USE_ONLY,
    U64,
    U20
);

impl_digest!(
    /// Structure representing the state of a SHA-256 computation
    Sha256,
    SHA256,
    U64,
    U32
);

impl_digest!(
    /// Structure representing the state of a SHA-384 computation
    Sha384,
    SHA384,
    U128,
    U48
);

impl_digest!(
    /// Structure representing the state of a SHA-512 computation
    Sha512,
    SHA512,
    U128,
    U64
);

impl_digest!(
    /// Structure representing the state of a SHA-512/256 computation
    Sha512Trunc256,
    SHA512_256,
    U128,
    U32
);
