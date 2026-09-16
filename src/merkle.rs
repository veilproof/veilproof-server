//! A fixed-depth Merkle tree over the BN254 scalar field, using the same MiMC
//! two-input hash as the circuit. The tree stores **leaf commitments** — the
//! hashes issuers compute off-chain from their real-world verification. It
//! never sees raw identities.
//!
//! Leaves are stored left-to-right; the tree is padded to `2^DEPTH` with a
//! fixed empty-leaf value so the root is always well-defined.

use ark_bn254::Fr;

use crate::crypto::circuit::DEPTH;
use crate::crypto::mimc::{hash2, round_constants};

/// A membership witness for one leaf: the sibling at each level and whether
/// the current node is the right child there.
#[derive(Clone, Debug)]
pub struct MerkleWitness {
    pub path_elements: Vec<Fr>,
    pub path_indices: Vec<bool>,
}

/// The value padding empty leaf slots. Distinct, fixed, and documented so the
/// root is deterministic for a given set of real leaves.
fn empty_leaf() -> Fr {
    Fr::from(0u64)
}

/// A depth-`DEPTH` Merkle tree of leaf commitments.
pub struct MerkleTree {
    constants: Vec<Fr>,
    leaves: Vec<Fr>,
}

impl MerkleTree {
    /// Maximum number of real leaves (`2^DEPTH`).
    pub const CAPACITY: usize = 1 << DEPTH;

    pub fn new() -> Self {
        Self {
            constants: round_constants(),
            leaves: Vec::new(),
        }
    }

    /// Rebuild a tree from a stored list of leaf commitments (e.g. from the
    /// database), preserving insertion order.
    pub fn from_leaves(leaves: Vec<Fr>) -> Result<Self, MerkleError> {
        if leaves.len() > Self::CAPACITY {
            return Err(MerkleError::Full);
        }
        Ok(Self {
            constants: round_constants(),
            leaves,
        })
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.leaves
    }

    /// Append a leaf commitment, returning its index.
    pub fn push(&mut self, leaf: Fr) -> Result<usize, MerkleError> {
        if self.leaves.len() >= Self::CAPACITY {
            return Err(MerkleError::Full);
        }
        self.leaves.push(leaf);
        Ok(self.leaves.len() - 1)
    }

    /// The full padded leaf layer.
    fn padded(&self) -> Vec<Fr> {
        let mut level = self.leaves.clone();
        level.resize(Self::CAPACITY, empty_leaf());
        level
    }

    /// The current Merkle root.
    pub fn root(&self) -> Fr {
        let mut level = self.padded();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                next.push(hash2(pair[0], pair[1], &self.constants));
            }
            level = next;
        }
        level[0]
    }

    /// The membership witness for the leaf at `index`.
    pub fn witness(&self, index: usize) -> Result<MerkleWitness, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfRange);
        }
        let mut level = self.padded();
        let mut path_elements = Vec::with_capacity(DEPTH);
        let mut path_indices = Vec::with_capacity(DEPTH);
        let mut idx = index;
        for _ in 0..DEPTH {
            let sibling = level[idx ^ 1];
            path_elements.push(sibling);
            path_indices.push(idx & 1 == 1);
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                next.push(hash2(pair[0], pair[1], &self.constants));
            }
            level = next;
            idx >>= 1;
        }
        Ok(MerkleWitness {
            path_elements,
            path_indices,
        })
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("the tree is full")]
    Full,
    #[error("leaf index out of range")]
    IndexOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_recomputes_root() {
        let mut tree = MerkleTree::new();
        for i in 0..5u64 {
            tree.push(Fr::from(100 + i)).unwrap();
        }
        let root = tree.root();
        let constants = round_constants();

        // Verify the witness for leaf 3 folds back up to the root.
        let idx = 3usize;
        let w = tree.witness(idx).unwrap();
        let mut cur = tree.leaves()[idx];
        for (sib, is_right) in w.path_elements.iter().zip(w.path_indices.iter()) {
            cur = if *is_right {
                hash2(*sib, cur, &constants)
            } else {
                hash2(cur, *sib, &constants)
            };
        }
        assert_eq!(cur, root);
    }

    #[test]
    fn rejects_overflow() {
        let mut tree = MerkleTree::new();
        for _ in 0..MerkleTree::CAPACITY {
            tree.push(Fr::from(1u64)).unwrap();
        }
        assert_eq!(tree.push(Fr::from(1u64)), Err(MerkleError::Full));
    }
}
