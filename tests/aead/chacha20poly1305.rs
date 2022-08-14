//! ChaCha20Poly1305 test vectors.
//!
//! From RFC 8439 Section 2.8.2:
//! <https://tools.ietf.org/html/rfc8439#section-2.8.2>

use ring_compat::{
    aead::{Aead, ChaCha20Poly1305, KeyInit, Payload},
    generic_array::GenericArray,
};

const KEY: &[u8; 32] = &[
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];

const AAD: &[u8; 12] = &[
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];

const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
    If I could offer you only one tip for the future, sunscreen would be it.";

const NONCE: &[u8; 12] = &[
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
];

const CIPHERTEXT: &[u8] = &[
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16,
];

const TAG: &[u8] = &[
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
];

#[test]
fn encrypt() {
    let key = GenericArray::from_slice(KEY);
    let nonce = GenericArray::from_slice(NONCE);
    let payload = Payload {
        msg: PLAINTEXT,
        aad: AAD,
    };

    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(nonce, payload).unwrap();

    let tag_begins = ciphertext.len() - 16;
    assert_eq!(CIPHERTEXT, &ciphertext[..tag_begins]);
    assert_eq!(TAG, &ciphertext[tag_begins..]);
}

#[test]
fn decrypt() {
    let key = GenericArray::from_slice(KEY);
    let nonce = GenericArray::from_slice(NONCE);

    let mut ciphertext = Vec::from(CIPHERTEXT);
    ciphertext.extend_from_slice(TAG);
    let payload = Payload {
        msg: &ciphertext,
        aad: AAD,
    };

    let cipher = ChaCha20Poly1305::new(key);
    let plaintext = cipher.decrypt(nonce, payload).unwrap();

    assert_eq!(PLAINTEXT, plaintext.as_slice());
}

#[test]
fn decrypt_modified() {
    let key = GenericArray::from_slice(KEY);
    let nonce = GenericArray::from_slice(NONCE);

    let mut ciphertext = Vec::from(CIPHERTEXT);
    ciphertext.extend_from_slice(TAG);

    // Tweak the first byte
    ciphertext[0] ^= 0xaa;

    let payload = Payload {
        msg: &ciphertext,
        aad: AAD,
    };

    let cipher = ChaCha20Poly1305::new(key);
    assert!(cipher.decrypt(nonce, payload).is_err());
}
