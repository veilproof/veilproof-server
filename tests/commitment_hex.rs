//! The hex encoding a holder actually handles.
//!
//! `veilproof-commit` prints a secret as hex and the holder pastes it back
//! later — into the CLI again, or into `POST /issuers/{name}/prove`. Both
//! paths decode it with `fr_from_be`. If that round trip were lossy the holder
//! would silently get a different commitment than the one the issuer put in
//! the tree, and proving would fail with nothing to point at.

use ark_bn254::Fr;
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use veilproof_server::crypto::{
    self,
    encoding::{fr_be, fr_from_be},
};

/// Decode the 64-hex-char form the CLI and the API both accept.
fn from_hex(s: &str) -> Fr {
    let arr: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
    fr_from_be(&arr)
}

#[test]
fn secret_survives_the_hex_round_trip() {
    let mut rng = ChaCha20Rng::seed_from_u64(20260917);
    for _ in 0..64 {
        let secret = Fr::rand(&mut rng);
        let printed = hex::encode(fr_be(&secret));
        assert_eq!(printed.len(), 64, "the CLI always prints 64 hex chars");
        assert_eq!(from_hex(&printed), secret);
        assert_eq!(
            crypto::leaf_commitment(from_hex(&printed)),
            crypto::leaf_commitment(secret),
            "a pasted-back secret must yield the issuer's commitment",
        );
    }
}

#[test]
fn small_secrets_are_left_padded_not_truncated() {
    // A secret near zero has leading zero bytes. Printing it unpadded would
    // produce a string the 32-byte parser rejects outright.
    let printed = hex::encode(fr_be(&Fr::from(7u64)));
    assert_eq!(
        printed,
        "0000000000000000000000000000000000000000000000000000000000000007"
    );
    assert_eq!(from_hex(&printed), Fr::from(7u64));
}

#[test]
fn distinct_secrets_give_distinct_commitments() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    assert_ne!(a, b);
    assert_ne!(crypto::leaf_commitment(a), crypto::leaf_commitment(b));
}

#[test]
fn a_commitment_does_not_leak_the_secret() {
    // The commitment is what the issuer stores and what anyone watching the
    // tree sees. It must not simply be the secret in disguise.
    let secret = Fr::from(12345u64);
    assert_ne!(crypto::leaf_commitment(secret), secret);
    assert_ne!(crypto::leaf_commitment(secret), crypto::nullifier(secret));
}
