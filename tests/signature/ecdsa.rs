//! ECDSA tests

mod p256;
mod p384;

#[macro_export]
macro_rules! ecdsa_tests {
    ($signing_key:ty, $verify_key:ty, $test_vectors:expr) => {
        fn example_signing_key() -> $signing_key {
            let vector = $test_vectors[0];

            // Add SEC1 tag byte
            let mut pk = vec![0x04];
            pk.extend_from_slice(vector.pk);

            <$signing_key>::from_keypair_bytes(vector.sk, &pk).unwrap()
        }

        #[test]
        fn sign_and_verify() {
            let signing_key = example_signing_key();
            let msg = $test_vectors[0].msg;
            let sig = signing_key.sign(msg);

            let verify_key = signing_key.verify_key();
            assert!(verify_key.verify(msg, &sig).is_ok());
        }

        #[test]
        fn verify_nist_test_vectors() {
            for vector in $test_vectors {
                let verify_key = <$verify_key>::new(vector.pk).unwrap();
                let sig = Signature::try_from(vector.sig).unwrap();
                assert!(verify_key.verify(vector.msg, &sig).is_ok());
            }
        }

        #[test]
        fn rejects_tweaked_nist_test_vectors() {
            for vector in $test_vectors {
                let mut tweaked_sig = Vec::from(vector.sig);
                *tweaked_sig.iter_mut().last().unwrap() ^= 0x42;

                let verify_key = <$verify_key>::new(vector.pk).unwrap();
                let sig = Signature::try_from(tweaked_sig.as_slice()).unwrap();
                assert!(verify_key.verify(vector.msg, &sig).is_err());
            }
        }
    };
}
