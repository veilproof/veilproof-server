//! The trust-critical core: circuit, trusted setup, proof generation, and the
//! Soroban-compatible encoding. Keep this module small and exhaustively
//! tested; resist adding unrelated features here.

pub mod circuit;
pub mod encoding;
pub mod mimc;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::merkle::MerkleTree;
use circuit::MerkleCircuit;
use encoding::{EncodedProof, EncodedVerifyingKey};
use mimc::{hash2, round_constants, LEAF_DOMAIN, NULLIFIER_DOMAIN};

/// A Groth16 key pair for the fixed circuit.
#[derive(Clone)]
pub struct Keys {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

impl Keys {
    /// The verifying key in the byte encoding `veilproof-registry`'s
    /// constructor expects.
    pub fn encoded_vk(&self) -> EncodedVerifyingKey {
        EncodedVerifyingKey::from_arkworks(&self.vk)
    }

    /// Persist the proving and verifying keys to `dir` as `pk.bin` / `vk.bin`
    /// (arkworks canonical, uncompressed for fast load).
    pub fn save(&self, dir: &std::path::Path) -> Result<(), KeyIoError> {
        std::fs::create_dir_all(dir)?;
        let mut pk_bytes = Vec::new();
        self.pk.serialize_uncompressed(&mut pk_bytes)?;
        std::fs::write(dir.join("pk.bin"), pk_bytes)?;
        let mut vk_bytes = Vec::new();
        self.vk.serialize_uncompressed(&mut vk_bytes)?;
        std::fs::write(dir.join("vk.bin"), vk_bytes)?;
        Ok(())
    }

    /// Load keys previously written by [`Keys::save`].
    pub fn load(dir: &std::path::Path) -> Result<Self, KeyIoError> {
        let pk_bytes = std::fs::read(dir.join("pk.bin"))?;
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed(&pk_bytes[..])?;
        let vk_bytes = std::fs::read(dir.join("vk.bin"))?;
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(&vk_bytes[..])?;
        Ok(Keys { pk, vk })
    }
}

/// Generate keys with the operating system's secure RNG. This is the
/// single-party production path: run it on a trusted machine, deploy the
/// registry with the resulting verifying key, and destroy the machine's state
/// so the toxic waste cannot be recovered. A multi-party ceremony is stronger
/// still; see the README.
pub fn generate_secure() -> Keys {
    setup(&mut rand::rngs::OsRng)
}

#[derive(Debug, thiserror::Error)]
pub enum KeyIoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
}

/// The deterministic seed used for the development trusted setup. It matches
/// `veilproof-registry`'s committed test vector so the two repos agree on the
/// verifying key byte-for-byte.
pub const DEV_SETUP_SEED: u64 = 0xF00D_BEEF;

/// Run the Groth16 trusted setup for the fixed circuit.
///
/// # Security
///
/// Whoever controls this RNG controls the setup's toxic waste, and anyone who
/// knows the toxic waste can forge proofs that verify — i.e. fake membership.
/// A real deployment MUST run this with cryptographically secure, private
/// randomness and destroy the toxic waste (ideally via a multi-party ceremony
/// or a universal setup). Do not ship a setup produced from a known seed.
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Keys {
    let circuit = MerkleCircuit::empty(round_constants());
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit, rng).expect("setup is infallible here");
    Keys { pk, vk }
}

/// A development key pair from a **known** seed — reproducible and therefore
/// **insecure**. Useful for tests and local runs; never for anything holding
/// value. See [`setup`].
pub fn dev_keys() -> Keys {
    let mut rng = ChaCha20Rng::seed_from_u64(DEV_SETUP_SEED);
    setup(&mut rng)
}

/// The leaf commitment for a secret: `H(secret, LEAF_DOMAIN)`. This is the
/// value an issuer stores in the tree; the server derives it and never learns
/// the real-world identity behind it.
pub fn leaf_commitment(secret: Fr) -> Fr {
    hash2(secret, Fr::from(LEAF_DOMAIN), &round_constants())
}

/// The nullifier for a secret: `H(secret, NULLIFIER_DOMAIN)`. Deterministic in
/// the secret alone, so the same credential always yields the same nullifier.
pub fn nullifier(secret: Fr) -> Fr {
    hash2(secret, Fr::from(NULLIFIER_DOMAIN), &round_constants())
}

/// A membership proof, encoded for direct submission to `veilproof-registry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    pub proof: EncodedProof,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Generate a real Groth16 membership proof for the holder of `secret` in
/// `tree`.
///
/// The server computes `leaf = H(secret, LEAF_DOMAIN)`, finds that commitment
/// in the tree, builds the inclusion witness, and proves. The secret is used
/// only to compute public, non-identifying values; it is never stored.
pub fn prove<R: RngCore + CryptoRng>(
    keys: &Keys,
    tree: &MerkleTree,
    secret: Fr,
    rng: &mut R,
) -> Result<MembershipProof, CryptoError> {
    let leaf = leaf_commitment(secret);
    let index = tree
        .leaves()
        .iter()
        .position(|l| *l == leaf)
        .ok_or(CryptoError::NotAMember)?;
    let witness = tree.witness(index).map_err(|_| CryptoError::NotAMember)?;

    let root = tree.root();
    let null = nullifier(secret);

    let circuit = MerkleCircuit {
        constants: round_constants(),
        root: Some(root),
        nullifier: Some(null),
        secret: Some(secret),
        path_elements: Some(witness.path_elements),
        path_indices: Some(witness.path_indices),
    };

    let proof =
        Groth16::<Bn254>::prove(&keys.pk, circuit, rng).map_err(|_| CryptoError::ProvingFailed)?;

    // Self-check before handing back bytes: a proof that doesn't even verify
    // locally must never be returned as if it were usable.
    let public_inputs = [root, null];
    let ok = Groth16::<Bn254>::verify(&keys.vk, &public_inputs, &proof)
        .map_err(|_| CryptoError::ProvingFailed)?;
    if !ok {
        return Err(CryptoError::ProvingFailed);
    }

    Ok(MembershipProof {
        proof: EncodedProof::from_arkworks(&proof),
        root: encoding::fr_be(&root),
        nullifier: encoding::fr_be(&null),
    })
}

/// Local Groth16 verification against the verifying key, for tests and
/// sanity checks. On-chain verification is the registry contract's job.
pub fn verify_local(keys: &Keys, proof: &ark_groth16::Proof<Bn254>, root: Fr, null: Fr) -> bool {
    Groth16::<Bn254>::verify(&keys.vk, &[root, null], proof).unwrap_or(false)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("the secret's commitment is not a leaf in this tree")]
    NotAMember,
    #[error("proof generation failed")]
    ProvingFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys survive a save/load round trip unchanged.
    #[test]
    fn keys_round_trip_through_disk() {
        let keys = dev_keys();
        let dir = std::env::temp_dir().join(format!("veilproof-keys-{}", std::process::id()));
        keys.save(&dir).unwrap();
        let loaded = Keys::load(&dir).unwrap();
        assert_eq!(keys.encoded_vk(), loaded.encoded_vk());
        std::fs::remove_dir_all(&dir).ok();
    }
}
