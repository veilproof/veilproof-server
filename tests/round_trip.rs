//! The centerpiece test (the project's CRITICAL FIRST STEP): a real Groth16
//! membership proof produced by this server, in Soroban's byte encoding, is
//! accepted by the actual veilproof-registry contract logic.
//!
//! It is demonstrated two ways:
//!
//! 1. `reproduces_registry_accepted_vector` — using the same circuit and the
//!    same deterministic setup as veilproof-registry's committed test vector,
//!    the server regenerates that vector **byte-for-byte**. Because
//!    veilproof-registry's CI proves Soroban's native `pairing_check` accepts
//!    those exact bytes, reproducing them ties this server's output to output
//!    the real contract is proven to accept. This is the encoding-correctness
//!    guarantee.
//!
//! 2. `arbitrary_tree_proof_verifies` — for an arbitrary tree the server
//!    builds itself, a freshly generated proof verifies under the same
//!    verifying key. Groth16 verification is what the registry's native host
//!    performs, so a proof valid under that key is one the contract accepts.

#[path = "common/registry_accepted_vector.rs"]
mod vector;

use ark_bn254::Fr;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use veilproof_server::crypto::{self, encoding, MembershipProof};
use veilproof_server::merkle::MerkleTree;

/// The fixed witness veilproof-registry's test vector was built from: a secret
/// whose commitment sits at leaf 0, with 15 other arbitrary leaves.
const FIXED_SECRET: u64 = 1_234_567_890;

/// The holder address the committed vector binds to (matches the registry
/// testvector). The proof is address-bound, so reproduction must use it.
const FIXED_HOLDER: &str = "GBYNOOC3UUF2QBCNIRUEHK2J3JOCDSV2QTLG445GW5ZEENPYDSU33OFQ";

fn fixed_tree() -> MerkleTree {
    let mut tree = MerkleTree::new();
    tree.push(crypto::leaf_commitment(Fr::from(FIXED_SECRET)))
        .unwrap();
    for j in 1..16u64 {
        tree.push(Fr::from(1000 + j)).unwrap();
    }
    tree
}

#[test]
fn reproduces_registry_accepted_vector() {
    // Same single RNG stream as the committed vector: setup, then prove.
    let mut rng = ChaCha20Rng::seed_from_u64(crypto::DEV_SETUP_SEED);
    let keys = crypto::setup(&mut rng);
    let tree = fixed_tree();
    let MembershipProof {
        proof,
        root,
        nullifier,
    } = crypto::prove(&keys, &tree, Fr::from(FIXED_SECRET), FIXED_HOLDER, &mut rng).unwrap();

    // Verifying key must match the key the contract is deployed with.
    let vk = keys.encoded_vk();
    assert_eq!(vk.alpha_g1, vector::ALPHA_G1, "alpha_g1 mismatch");
    assert_eq!(vk.beta_g2, vector::BETA_G2, "beta_g2 mismatch");
    assert_eq!(vk.gamma_g2, vector::GAMMA_G2, "gamma_g2 mismatch");
    assert_eq!(vk.delta_g2, vector::DELTA_G2, "delta_g2 mismatch");
    assert_eq!(vk.ic.len(), vector::IC.len(), "ic length mismatch");
    assert_eq!(
        vk.ic.len(),
        4,
        "circuit should have 4 IC entries (one + 3 public inputs)"
    );
    for (got, want) in vk.ic.iter().zip(vector::IC.iter()) {
        assert_eq!(got, want, "ic entry mismatch");
    }

    // The server's address derivation matches the vector's bound address.
    assert_eq!(
        encoding::fr_be(&crypto::address_field(FIXED_HOLDER)),
        vector::PUB_ADDR,
        "address derivation mismatch"
    );

    // Proof and public inputs must match the accepted bytes exactly.
    assert_eq!(proof.a, vector::PROOF_A, "proof.a mismatch");
    assert_eq!(proof.b, vector::PROOF_B, "proof.b mismatch");
    assert_eq!(proof.c, vector::PROOF_C, "proof.c mismatch");
    assert_eq!(root, vector::PUB_ROOT, "root mismatch");
    assert_eq!(nullifier, vector::PUB_NULLIFIER, "nullifier mismatch");
}

#[test]
fn arbitrary_tree_proof_verifies() {
    let mut rng = ChaCha20Rng::seed_from_u64(crypto::DEV_SETUP_SEED);
    let keys = crypto::setup(&mut rng);

    // A tree the server builds itself, with the holder's commitment somewhere
    // in the middle.
    let secret = Fr::from(987_654_321u64);
    let mut tree = MerkleTree::new();
    tree.push(Fr::from(11u64)).unwrap();
    tree.push(Fr::from(22u64)).unwrap();
    tree.push(crypto::leaf_commitment(secret)).unwrap(); // index 2
    tree.push(Fr::from(44u64)).unwrap();

    let mp = crypto::prove(&keys, &tree, secret, FIXED_HOLDER, &mut rng).unwrap();

    // The encoded public values agree with a direct recomputation.
    assert_eq!(mp.root, encoding::fr_be(&tree.root()));
    assert_eq!(mp.nullifier, encoding::fr_be(&crypto::nullifier(secret)));

    // And it verifies under the verifying key — which is what the registry's
    // native pairing_check does on-chain.
    let re = regenerate(&keys, &tree, secret);
    assert!(crypto::verify_local(
        &keys,
        &re,
        tree.root(),
        crypto::nullifier(secret),
        crypto::address_field(FIXED_HOLDER),
    ));
}

#[test]
fn non_member_cannot_prove() {
    let mut rng = ChaCha20Rng::seed_from_u64(crypto::DEV_SETUP_SEED);
    let keys = crypto::setup(&mut rng);
    let mut tree = MerkleTree::new();
    tree.push(Fr::from(1u64)).unwrap();
    tree.push(Fr::from(2u64)).unwrap();

    // A secret whose commitment is not in the tree.
    let outsider = Fr::from(424_242u64);
    let res = crypto::prove(&keys, &tree, outsider, FIXED_HOLDER, &mut rng);
    assert_eq!(res, Err(crypto::CryptoError::NotAMember));
}

/// Re-run proving to get the raw arkworks proof for a local verify check
/// (the public `prove` returns encoded bytes, not the arkworks type).
fn regenerate(
    keys: &crypto::Keys,
    tree: &MerkleTree,
    secret: Fr,
) -> ark_groth16::Proof<ark_bn254::Bn254> {
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use veilproof_server::crypto::circuit::MerkleCircuit;
    use veilproof_server::crypto::mimc::round_constants;

    let leaf = crypto::leaf_commitment(secret);
    let index = tree.leaves().iter().position(|l| *l == leaf).unwrap();
    let w = tree.witness(index).unwrap();
    let circuit = MerkleCircuit {
        constants: round_constants(),
        root: Some(tree.root()),
        nullifier: Some(crypto::nullifier(secret)),
        addr: Some(crypto::address_field(FIXED_HOLDER)),
        secret: Some(secret),
        path_elements: Some(w.path_elements),
        path_indices: Some(w.path_indices),
    };
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    Groth16::<ark_bn254::Bn254>::prove(&keys.pk, circuit, &mut rng).unwrap()
}
