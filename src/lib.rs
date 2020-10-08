//! [`aead::Aead`] trait wrappers for the high-performance implementations of
//! AES-GCM and ChaCha20Poly1305 from the *ring* crate.

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

pub use aead;
pub use digest::{self, Digest};

use aead::{
    consts::{U0, U12, U16, U32},
    AeadInPlace, Buffer, Error, NewAead,
};
use core::mem;
use digest::{
    generic_array::{typenum::*, GenericArray},
    BlockInput, FixedOutput, Reset, Update,
};
use ring::aead::LessSafeKey as Key; // (^～^;)ゞ
use ring::aead::{Aad, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use ring::digest::Context;
use zeroize::Zeroize;

/// Authentication tags
pub type Tag = GenericArray<u8, U16>;

/// AES-GCM with a 128-bit key
pub struct Aes128Gcm(GenericArray<u8, U16>);

/// AES-GCM with a 256-bit key
pub struct Aes256Gcm(GenericArray<u8, U32>);

/// ChaCha20Poly1305
pub struct ChaCha20Poly1305(GenericArray<u8, U32>);

macro_rules! impl_aead {
    ($cipher:ty, $algorithm:expr, $key_size:ty) => {
        impl NewAead for $cipher {
            type KeySize = $key_size;

            fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
                Self(*key)
            }
        }

        impl AeadInPlace for $cipher {
            type NonceSize = U12;
            type TagSize = U16;
            type CiphertextOverhead = U0;

            fn encrypt_in_place_detached(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> Result<Tag, Error> {
                let key = UnboundKey::new(&$algorithm, self.0.as_slice()).unwrap();
                Cipher::new(key).encrypt_in_place_detached(
                    nonce.as_slice(),
                    associated_data,
                    buffer,
                )
            }

            fn decrypt_in_place(
                &self,
                nonce: &GenericArray<u8, Self::NonceSize>,
                associated_data: &[u8],
                buffer: &mut dyn Buffer,
            ) -> Result<(), Error> {
                let key = UnboundKey::new(&$algorithm, self.0.as_slice()).unwrap();
                Cipher::new(key).decrypt_in_place(nonce.as_slice(), associated_data, buffer)
            }

            fn decrypt_in_place_detached(
                &self,
                _nonce: &GenericArray<u8, Self::NonceSize>,
                _associated_data: &[u8],
                _buffer: &mut [u8],
                _tag: &Tag,
            ) -> Result<(), Error> {
                unimplemented!(); // ring does not allow us to implement this API
            }
        }

        impl Drop for $cipher {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
    };
}

impl_aead!(Aes128Gcm, AES_128_GCM, U16);
impl_aead!(Aes256Gcm, AES_256_GCM, U32);
impl_aead!(ChaCha20Poly1305, CHACHA20_POLY1305, U32);

/// Generic AEAD cipher support
pub(crate) struct Cipher(Key);

impl Cipher {
    /// Instantiate a particular AEAD algorithm
    pub fn new(key: UnboundKey) -> Self {
        Cipher(Key::new(key))
    }

    /// Encrypt the ciphertext in place, returning a tag
    fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        self.0
            .seal_in_place_separate_tag(
                Nonce::try_assume_unique_for_key(nonce).unwrap(),
                Aad::from(associated_data),
                buffer,
            )
            .map(|tag| Tag::clone_from_slice(tag.as_ref()))
            .map_err(|_| Error)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        let pt_len = self
            .0
            .open_in_place(
                Nonce::try_assume_unique_for_key(nonce).unwrap(),
                Aad::from(associated_data),
                buffer.as_mut(),
            )
            .map_err(|_| Error)?
            .len();

        buffer.truncate(pt_len);
        Ok(())
    }
}

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
            fn update(&mut self, data: impl AsRef<[u8]>) {
                self.0.update(data.as_ref())
            }
        }

        impl BlockInput for $name {
            type BlockSize = $block_len;
        }

        impl FixedOutput for $name {
            type OutputSize = $output_size;

            fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
                *out = GenericArray::clone_from_slice(self.0.finish().as_ref());
            }

            fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
                *out = GenericArray::clone_from_slice(self.take().finish().as_ref());
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                mem::drop(self.take());
            }
        }

        digest::impl_write!($name);
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
