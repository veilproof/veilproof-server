//! Holder-side handler: generate a membership proof.
//!
//! Privacy: the holder submits their own secret directly here. The server
//! derives `leaf = H(secret, LEAF_DOMAIN)`, checks it is in the tree, builds
//! the proof, and returns it. The secret is never stored or logged, and the
//! server never learns which real-world identity the leaf belongs to — it only
//! ever sees commitments. Do not log the request body.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use super::{parse_fr_hex, ApiError, AppState};
use crate::crypto::{self, encoding::fr_be};
use crate::merkle::MerkleTree;

#[derive(Deserialize)]
pub struct ProveRequest {
    /// The holder's own secret, 64 hex chars. Known only to the holder,
    /// submitted directly, never stored.
    pub secret: String,
    /// The Stellar address (strkey) the holder will submit from. The proof is
    /// bound to it, so it must match the address that calls the contract.
    pub holder_address: String,
}

#[derive(Serialize)]
pub struct ProveResponse {
    pub proof: ProofJson,
    /// Public input: the Merkle root the proof is against (matches on-chain).
    pub root: String,
    /// Public input: the nullifier to submit alongside the proof.
    pub nullifier: String,
}

/// The Groth16 proof, hex-encoded in Soroban's byte layout, ready to pass to
/// `veilproof-registry`'s `verify_credential`.
#[derive(Serialize)]
pub struct ProofJson {
    pub a: String,
    pub b: String,
    pub c: String,
}

/// `POST /issuers/{name}/prove` — produce a membership proof for the holder.
pub async fn prove(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, ApiError> {
    let secret = parse_fr_hex(&req.secret)?;

    let leaves = state.store.leaves(&name).await?;
    if leaves.is_empty() {
        return Err(ApiError::NotFound("no such issuer, or empty tree".into()));
    }
    let tree = MerkleTree::from_leaves(leaves)
        .map_err(|_| ApiError::Conflict("the tree is full".into()))?;

    // The proof's root is a public input the contract checks against its
    // on-chain root. Refuse to prove against a tree that has changed since the
    // last publish, so we never hand back a proof the contract will reject.
    match state.store.published_root(&name).await? {
        Some(published) if published == tree.root() => {}
        Some(_) => {
            return Err(ApiError::Conflict(
                "the tree has changed since the last publish; the issuer must publish (and submit) the current root first".into(),
            ))
        }
        None => {
            return Err(ApiError::Conflict(
                "no root has been published for this issuer yet".into(),
            ))
        }
    }

    // Groth16 proving is CPU-bound and takes seconds — far too long to sit on
    // an async worker thread. Blocking the runtime stalls every other task on
    // it, including /health, so a platform health check starts failing and the
    // instance gets restarted mid-proof. On a host with a fraction of a core
    // that is fatal: the request 502s and takes the service down with it.
    // spawn_blocking moves the work to a pool meant for exactly this.
    let keys = Arc::clone(&state.keys);
    let holder_address = req.holder_address.clone();
    let membership = tokio::task::spawn_blocking(move || {
        let mut rng = OsRng;
        crypto::prove(&keys, &tree, secret, &holder_address, &mut rng)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("the proving task failed: {e}")))??;

    // Bookkeeping only — the contract remains authoritative for on-chain use.
    let nullifier = crypto::nullifier(secret);
    if let Err(e) = state.store.record_nullifier(&name, nullifier).await {
        tracing::warn!(error = %e, "failed to record generated nullifier (non-fatal)");
    }

    Ok(Json(ProveResponse {
        proof: ProofJson {
            a: hex::encode(membership.proof.a),
            b: hex::encode(membership.proof.b),
            c: hex::encode(membership.proof.c),
        },
        root: hex::encode(membership.root),
        nullifier: hex::encode(fr_be(&nullifier)),
    }))
}
