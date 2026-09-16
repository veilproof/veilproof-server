//! The one fixed circuit: Merkle-membership + nullifier.
//!
//! Proves, in zero knowledge, that the prover knows a `secret` whose leaf
//! commitment `H(secret, LEAF_DOMAIN)` sits at some position in a Merkle tree
//! with the given public `root`, and binds a public `nullifier =
//! H(secret, NULLIFIER_DOMAIN)`. The nullifier is a deterministic function of
//! the secret alone, so the same underlying credential always yields the same
//! nullifier — which is what lets the registry contract prevent it being used
//! twice.
//!
//! Public inputs, in this exact order (the contract's `vk.ic` matches it):
//!   1. root
//!   2. nullifier
//!   3. addr — the holder address bound to the proof, so it cannot be replayed
//!      by another party

use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::{Boolean, CondSelectGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::mimc::{hash2_gadget, LEAF_DOMAIN, NULLIFIER_DOMAIN};

/// Merkle tree depth the circuit is built for. Fixed at circuit-definition
/// time because the number of constraints depends on it — changing it changes
/// the verifying key.
pub const DEPTH: usize = 4;

/// The circuit and its witness. Witness fields are `Option` so the same type
/// serves both the (witness-free) trusted setup and proving.
#[derive(Clone)]
pub struct MerkleCircuit {
    /// MiMC round constants (public circuit parameter).
    pub constants: Vec<Fr>,
    // public inputs
    pub root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub addr: Option<Fr>,
    // private witness
    pub secret: Option<Fr>,
    pub path_elements: Option<Vec<Fr>>,
    pub path_indices: Option<Vec<bool>>,
}

impl MerkleCircuit {
    /// A witness-free instance for the trusted setup.
    pub fn empty(constants: Vec<Fr>) -> Self {
        Self {
            constants,
            root: None,
            nullifier: None,
            addr: None,
            secret: None,
            path_elements: None,
            path_indices: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for MerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // The holder address, bound as a public input. Not tied to the
        // witness — the verifier supplies it (derived from the caller) so a
        // proof only verifies for the address it was generated for. One
        // multiplication gate keeps it a real part of the constraint system.
        let addr = FpVar::new_input(cs.clone(), || {
            self.addr.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _addr_bound = &addr * &addr;
        let secret = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // leaf = H(secret, LEAF_DOMAIN)
        let leaf_domain = FpVar::constant(Fr::from(LEAF_DOMAIN));
        let mut cur = hash2_gadget(&secret, &leaf_domain, &self.constants)?;

        for i in 0..DEPTH {
            let sib = FpVar::new_witness(cs.clone(), || {
                self.path_elements
                    .as_ref()
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let bit = Boolean::new_witness(cs.clone(), || {
                self.path_indices
                    .as_ref()
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            // bit = true means `cur` is the right child: hash(sibling, cur).
            let left = FpVar::conditionally_select(&bit, &sib, &cur)?;
            let right = FpVar::conditionally_select(&bit, &cur, &sib)?;
            cur = hash2_gadget(&left, &right, &self.constants)?;
        }
        cur.enforce_equal(&root)?;

        let null_domain = FpVar::constant(Fr::from(NULLIFIER_DOMAIN));
        let null_calc = hash2_gadget(&secret, &null_domain, &self.constants)?;
        null_calc.enforce_equal(&nullifier)?;

        Ok(())
    }
}
