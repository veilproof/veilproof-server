//! MiMC hash over the BN254 scalar field, in both native and gadget form.
//!
//! This is the ZK-friendly hash used for the Merkle tree and the nullifier.
//! The native and gadget implementations MUST stay bit-identical: the native
//! side computes the witness, the gadget side constrains it, and any
//! divergence makes proofs that don't verify.
//!
//! Note on choice: MiMC is a deliberately minimal, well-understood SNARK hash
//! (`t^5` per round over the scalar field) that is simple enough to implement
//! correctly by hand in both forms. Poseidon is the more common production
//! choice; adopting it is tracked as future work. What matters for the MVP is
//! that the hash is arithmetic-circuit-friendly and that the two
//! implementations provably agree — see the `native_and_gadget_agree` test.

use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;

/// Number of MiMC rounds. The proof's soundness comes from Groth16; this
/// count only needs to make the permutation non-trivial.
pub const ROUNDS: usize = 91;

/// Domain separator for a leaf commitment: `leaf = H(secret, LEAF_DOMAIN)`.
pub const LEAF_DOMAIN: u64 = 1;
/// Domain separator for the nullifier: `nullifier = H(secret, NULLIFIER_DOMAIN)`.
pub const NULLIFIER_DOMAIN: u64 = 2;

/// Deterministic round constants. Fixed and reproducible so the circuit — and
/// therefore the verifying key — is identical everywhere it is built.
pub fn round_constants() -> Vec<Fr> {
    let mut cs = Vec::with_capacity(ROUNDS);
    let mut state: u128 = 0xDEAD_BEEF_CAFE_BABE_0123_4567_89AB_CDEF;
    for _ in 0..ROUNDS {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        cs.push(Fr::from(state));
    }
    cs
}

/// Native MiMC permutation of `x` under key `k`.
fn mimc(mut x: Fr, k: Fr, constants: &[Fr]) -> Fr {
    for c in constants {
        let t = x + k + c;
        let t2 = t * t;
        let t4 = t2 * t2;
        x = t4 * t; // t^5
    }
    x + k
}

/// Native two-input hash. Miyaguchi–Preneel-style feed-forward of both inputs.
pub fn hash2(l: Fr, r: Fr, constants: &[Fr]) -> Fr {
    mimc(l, r, constants) + l + r
}

/// Gadget MiMC permutation — the in-circuit counterpart of [`mimc`].
fn mimc_gadget(
    x: &FpVar<Fr>,
    k: &FpVar<Fr>,
    constants: &[Fr],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut x = x.clone();
    for c in constants {
        let t = &x + k + FpVar::constant(*c);
        let t2 = &t * &t;
        let t4 = &t2 * &t2;
        x = &t4 * &t;
    }
    Ok(&x + k)
}

/// Gadget two-input hash — the in-circuit counterpart of [`hash2`].
pub fn hash2_gadget(
    l: &FpVar<Fr>,
    r: &FpVar<Fr>,
    constants: &[Fr],
) -> Result<FpVar<Fr>, SynthesisError> {
    let h = mimc_gadget(l, r, constants)?;
    Ok(&h + l + r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    /// The native and gadget hashes must produce the same value for the same
    /// input — the invariant the whole proving pipeline depends on.
    #[test]
    fn native_and_gadget_agree() {
        let constants = round_constants();
        let l = Fr::from(42u64);
        let r = Fr::from(1337u64);
        let native = hash2(l, r, &constants);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let lv = FpVar::new_witness(cs.clone(), || Ok(l)).unwrap();
        let rv = FpVar::new_witness(cs.clone(), || Ok(r)).unwrap();
        let gadget = hash2_gadget(&lv, &rv, &constants).unwrap();
        assert_eq!(gadget.value().unwrap(), native);
        assert!(cs.is_satisfied().unwrap());
    }
}
