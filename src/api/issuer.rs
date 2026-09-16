//! Issuer-side handlers: manage a named Merkle tree and publish its root.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::{parse_fr_hex, ApiError, AppState};
use crate::crypto::encoding::fr_be;
use crate::merkle::MerkleTree;

#[derive(Deserialize)]
pub struct AddLeafRequest {
    /// Leaf commitment as 64 hex chars — a hash the issuer computed off-chain
    /// from whatever real-world verification they did. Never raw PII.
    pub commitment: String,
}

#[derive(Serialize)]
pub struct AddLeafResponse {
    pub position: usize,
    pub count: usize,
}

/// `POST /issuers/{name}/leaves` — add a credential-holder commitment.
pub async fn add_leaf(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<AddLeafRequest>,
) -> Result<Json<AddLeafResponse>, ApiError> {
    let commitment = parse_fr_hex(&req.commitment)?;
    let (position, count) = state.store.add_leaf(&name, commitment).await?;
    Ok(Json(AddLeafResponse { position, count }))
}

#[derive(Serialize)]
pub struct RootResponse {
    /// The Merkle root as 64 hex chars, ready to submit on-chain.
    pub root: String,
}

/// `POST /issuers/{name}/publish` — recompute the current root, persist it,
/// and return it.
///
/// This is the safer default: the server returns the root and the issuer
/// submits it on-chain themselves with their own signing setup. Submitting on
/// the issuer's behalf would require the server to hold a signing key — more
/// convenient, but it makes the server a custodian of on-chain authority and a
/// higher-value target. That path is intentionally not part of the MVP; see
/// the README.
pub async fn publish(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<RootResponse>, ApiError> {
    let leaves = state.store.leaves(&name).await?;
    if leaves.is_empty() {
        return Err(ApiError::BadRequest(
            "cannot publish an empty tree — add leaves first".into(),
        ));
    }
    let tree = MerkleTree::from_leaves(leaves)
        .map_err(|_| ApiError::Conflict("the tree is full".into()))?;
    let root = tree.root();
    state.store.set_published_root(&name, root).await?;
    Ok(Json(RootResponse {
        root: hex::encode(fr_be(&root)),
    }))
}

/// `GET /issuers/{name}/root` — the current published root.
pub async fn get_root(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<RootResponse>, ApiError> {
    match state.store.published_root(&name).await? {
        Some(root) => Ok(Json(RootResponse {
            root: hex::encode(fr_be(&root)),
        })),
        None => Err(ApiError::NotFound(
            "no root has been published for this issuer".into(),
        )),
    }
}

#[derive(Serialize)]
pub struct IssuersListResponse {
    pub issuers: Vec<String>,
}

/// `GET /issuers` — list all known issuer names.
pub async fn list_issuers(
    State(state): State<AppState>,
) -> Result<Json<IssuersListResponse>, ApiError> {
    let issuers = state.store.list_issuers().await?;
    Ok(Json(IssuersListResponse { issuers }))
}

#[derive(Serialize)]
pub struct IssuerInfoResponse {
    pub name: String,
    pub leaf_count: usize,
    pub capacity: usize,
    /// The last published root as hex, or null if never published.
    pub published_root: Option<String>,
}

/// `GET /issuers/{name}` — summary of an issuer's tree.
pub async fn issuer_info(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<IssuerInfoResponse>, ApiError> {
    if !state.store.issuer_exists(&name).await? {
        return Err(ApiError::NotFound("no such issuer".into()));
    }
    let leaf_count = state.store.leaf_count(&name).await?;
    let published_root = state
        .store
        .published_root(&name)
        .await?
        .map(|r| hex::encode(fr_be(&r)));
    Ok(Json(IssuerInfoResponse {
        name,
        leaf_count,
        capacity: MerkleTree::CAPACITY,
        published_root,
    }))
}
