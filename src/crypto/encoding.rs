//! Serialization of a Groth16 verifying key and proof into the EXACT byte
//! encoding Soroban's native BN254 host functions expect (CAP-0074), which
//! `veilproof-registry` consumes. This is the conversion layer the project
//! brief demands: arkworks' native serialization does NOT match Soroban's, so
//! nothing here relies on arkworks' `CanonicalSerialize`.
//!
//! The rules, each the opposite of an arkworks default (see the registry
//! README's "BN254 Encoding Notes"):
//!   - field elements are big-endian (arkworks is little-endian);
//!   - points are uncompressed;
//!   - Fp2 is ordered `c1 ‖ c0` (arkworks stores `c0, c1`).
//!
//! Layouts:
//!   Fp / Fr : 32 bytes, big-endian
//!   G1      : be(X) ‖ be(Y)                             = 64 bytes
//!   G2      : be(X.c1) ‖ be(X.c0) ‖ be(Y.c1) ‖ be(Y.c0) = 128 bytes
//!   ∞       : all-zero bytes

use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};

/// A base-field element as 32 big-endian bytes.
fn fq_be(x: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

/// Parse a scalar from 32 big-endian bytes, reducing modulo the field order.
/// Commitments and nullifiers are already field elements, so this round-trips
/// values produced by [`fr_be`].
pub fn fr_from_be(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// A scalar as 32 big-endian bytes.
pub fn fr_be(x: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

/// G1 point → 64 bytes: `be(X) ‖ be(Y)`, uncompressed. Infinity → all zeros.
pub fn g1_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.infinity {
        return out;
    }
    out[..32].copy_from_slice(&fq_be(&p.x));
    out[32..].copy_from_slice(&fq_be(&p.y));
    out
}

/// G2 point → 128 bytes: `be(X.c1) ‖ be(X.c0) ‖ be(Y.c1) ‖ be(Y.c0)`,
/// uncompressed. Note the c1-before-c0 order. Infinity → all zeros.
pub fn g2_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.infinity {
        return out;
    }
    out[0..32].copy_from_slice(&fq_be(&p.x.c1));
    out[32..64].copy_from_slice(&fq_be(&p.x.c0));
    out[64..96].copy_from_slice(&fq_be(&p.y.c1));
    out[96..128].copy_from_slice(&fq_be(&p.y.c0));
    out
}

/// The verifying key in Soroban encoding — the bytes `veilproof-registry`'s
/// constructor takes. `ic` has one entry per public input plus a constant
/// term, so length 3 for this circuit `(root, nullifier)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedVerifyingKey {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: Vec<[u8; 64]>,
}

/// The proof in Soroban encoding — the bytes passed to `verify_credential`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedProof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

impl EncodedVerifyingKey {
    pub fn from_arkworks(vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> Self {
        Self {
            alpha_g1: g1_bytes(&vk.alpha_g1),
            beta_g2: g2_bytes(&vk.beta_g2),
            gamma_g2: g2_bytes(&vk.gamma_g2),
            delta_g2: g2_bytes(&vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(g1_bytes).collect(),
        }
    }
}

impl EncodedProof {
    pub fn from_arkworks(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> Self {
        Self {
            a: g1_bytes(&proof.a),
            b: g2_bytes(&proof.b),
            c: g1_bytes(&proof.c),
        }
    }
}
