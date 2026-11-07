//! The proving path as WebAssembly: the same circuit, Merkle tree and encoding
//! as the server, run on the holder's own machine so their secret stays there.
//!
//! The interface is deliberately thin. A caller loads the trusted-setup keys
//! once with `vp_load_keys`, then sends JSON requests through `vp_call`, so there
//! is no generated glue to keep in step and it runs in a browser or Node alike.
//!
//! This crate draws no randomness of its own. Secrets and proofs are seeded by
//! the caller, which has to use a cryptographically secure source: in a browser,
//! `crypto.getRandomValues`.

use ark_bn254::Fr;
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use veilproof_server::crypto::encoding::{fr_be, fr_from_be};
use veilproof_server::crypto::{self, CryptoError, Keys};
use veilproof_server::merkle::MerkleTree;

/// A request, as JSON with its kind under `op`.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    /// Mint a secret and its commitment.
    NewSecret { seed: String },
    /// Recompute the commitment for a secret the holder already has.
    Commitment { secret: String },
    /// The root of a tree of leaf commitments.
    Root { leaves: Vec<String> },
    /// A membership proof bound to `holder`. Needs the keys to be loaded.
    Prove {
        leaves: Vec<String>,
        secret: String,
        holder: String,
        seed: String,
    },
    /// The digest of the loaded verifying key, comparable with `VEILPROOF_VK_SHA256`.
    VkDigest,
    /// The loaded verifying key in the encoding `register_circuit` takes.
    VerifyingKey,
}

/// Answer a JSON request given the keys, if they have been loaded. Every failure
/// comes back as `{"error": ...}`, because a trap would take the module with it.
pub fn handle(request: &str, keys: Option<&Keys>) -> String {
    let answer = serde_json::from_str::<Request>(request)
        .map_err(|e| format!("bad request: {e}"))
        .and_then(|request| answer(request, keys));
    match answer {
        Ok(value) => value.to_string(),
        Err(error) => json!({ "error": error }).to_string(),
    }
}

fn answer(request: Request, keys: Option<&Keys>) -> Result<Value, String> {
    match request {
        Request::NewSecret { seed } => {
            let secret = Fr::rand(&mut rng_from(&seed)?);
            Ok(json!({
                "secret": to_hex(&secret),
                "commitment": to_hex(&crypto::leaf_commitment(secret)),
            }))
        }
        Request::Commitment { secret } => {
            let secret = parse_field(&secret, "secret")?;
            Ok(json!({ "commitment": to_hex(&crypto::leaf_commitment(secret)) }))
        }
        Request::Root { leaves } => {
            let tree = parse_tree(&leaves)?;
            Ok(json!({
                "root": to_hex(&tree.root()),
                "capacity": MerkleTree::CAPACITY,
            }))
        }
        Request::Prove {
            leaves,
            secret,
            holder,
            seed,
        } => {
            let keys = keys.ok_or("the proving keys are not loaded")?;
            let tree = parse_tree(&leaves)?;
            let secret = parse_field(&secret, "secret")?;
            let mut rng = rng_from(&seed)?;
            let membership =
                crypto::prove(keys, &tree, secret, &holder, &mut rng).map_err(|e| match e {
                    CryptoError::NotAMember => {
                        "this secret's commitment is not in the tree".to_string()
                    }
                    other => other.to_string(),
                })?;
            Ok(json!({
                "proof": {
                    "a": hex::encode(membership.proof.a),
                    "b": hex::encode(membership.proof.b),
                    "c": hex::encode(membership.proof.c),
                },
                "root": hex::encode(membership.root),
                "nullifier": hex::encode(membership.nullifier),
            }))
        }
        Request::VkDigest => {
            let keys = keys.ok_or("the proving keys are not loaded")?;
            Ok(json!({ "digest": hex::encode(keys.vk_digest()) }))
        }
        Request::VerifyingKey => {
            let vk = keys.ok_or("the proving keys are not loaded")?.encoded_vk();
            Ok(json!({
                "alpha_g1": hex::encode(vk.alpha_g1),
                "beta_g2": hex::encode(vk.beta_g2),
                "gamma_g2": hex::encode(vk.gamma_g2),
                "delta_g2": hex::encode(vk.delta_g2),
                "ic": vk.ic.iter().map(hex::encode).collect::<Vec<_>>(),
            }))
        }
    }
}

fn to_hex(value: &Fr) -> String {
    hex::encode(fr_be(value))
}

fn parse_bytes32(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| format!("{name} must be 32 bytes of hex (64 characters)"))
}

/// Parse a field element, refusing one at or above the field order. Reducing it
/// instead would quietly hash to a different value from the one pasted in, and
/// the mismatch would only surface later as a proof that fails.
fn parse_field(value: &str, name: &str) -> Result<Fr, String> {
    let bytes = parse_bytes32(value, name)?;
    let field = fr_from_be(&bytes);
    if fr_be(&field) != bytes {
        return Err(format!("{name} is not a valid field element"));
    }
    Ok(field)
}

fn parse_tree(leaves: &[String]) -> Result<MerkleTree, String> {
    let leaves = leaves
        .iter()
        .map(|leaf| parse_field(leaf, "a leaf commitment"))
        .collect::<Result<Vec<_>, _>>()?;
    MerkleTree::from_leaves(leaves).map_err(|e| e.to_string())
}

fn rng_from(seed: &str) -> Result<ChaCha20Rng, String> {
    Ok(ChaCha20Rng::from_seed(parse_bytes32(seed, "seed")?))
}

/// The WebAssembly surface: raw exports over the module's linear memory.
#[cfg(target_arch = "wasm32")]
mod exports {
    use std::alloc::{alloc, dealloc, Layout};
    use std::sync::{Mutex, OnceLock};

    use super::{handle, Keys};

    static KEYS: OnceLock<Keys> = OnceLock::new();
    static RESULT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    // Reached only through OsRng, which this crate never uses. Failing here is
    // the point: a proof must never be seeded from anything but the caller.
    fn no_entropy(_: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
    getrandom::register_custom_getrandom!(no_entropy);

    /// Reserve `len` bytes for the caller to write into.
    #[no_mangle]
    pub extern "C" fn vp_alloc(len: usize) -> *mut u8 {
        unsafe { alloc(Layout::from_size_align(len.max(1), 1).unwrap()) }
    }

    /// Release memory from [`vp_alloc`].
    ///
    /// # Safety
    /// `ptr` and `len` must be exactly what `vp_alloc` was called with and returned.
    #[no_mangle]
    pub unsafe extern "C" fn vp_free(ptr: *mut u8, len: usize) {
        dealloc(ptr, Layout::from_size_align(len.max(1), 1).unwrap());
    }

    /// Parse and store the trusted-setup keys. Returns 1 on success, 0 if the
    /// bytes are not valid keys.
    ///
    /// # Safety
    /// Both ranges must be initialized memory from [`vp_alloc`].
    #[no_mangle]
    pub unsafe extern "C" fn vp_load_keys(
        pk: *const u8,
        pk_len: usize,
        vk: *const u8,
        vk_len: usize,
    ) -> u32 {
        let pk = std::slice::from_raw_parts(pk, pk_len);
        let vk = std::slice::from_raw_parts(vk, vk_len);
        match Keys::from_bytes(pk, vk) {
            Ok(keys) => {
                let _ = KEYS.set(keys);
                1
            }
            Err(_) => 0,
        }
    }

    /// Answer a JSON request. The response is then available through
    /// [`vp_result_ptr`] and [`vp_result_len`] until the next call.
    ///
    /// # Safety
    /// The range must be initialized memory from [`vp_alloc`].
    #[no_mangle]
    pub unsafe extern "C" fn vp_call(ptr: *const u8, len: usize) {
        let request = std::slice::from_raw_parts(ptr, len);
        let response = match std::str::from_utf8(request) {
            Ok(request) => handle(request, KEYS.get()),
            Err(_) => r#"{"error":"the request is not valid UTF-8"}"#.to_string(),
        };
        *RESULT.lock().unwrap() = response.into_bytes();
    }

    #[no_mangle]
    pub extern "C" fn vp_result_ptr() -> *const u8 {
        RESULT.lock().unwrap().as_ptr()
    }

    #[no_mangle]
    pub extern "C" fn vp_result_len() -> usize {
        RESULT.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veilproof_server::crypto::dev_keys;

    const HOLDER: &str = "GBYNOOC3UUF2QBCNIRUEHK2J3JOCDSV2QTLG445GW5ZEENPYDSU33OFQ";
    const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SECRET_7: &str = "0000000000000000000000000000000000000000000000000000000000000007";

    fn call(request: Value, keys: Option<&Keys>) -> Value {
        serde_json::from_str(&handle(&request.to_string(), keys)).unwrap()
    }

    fn commitment_of(secret: &str) -> String {
        call(json!({ "op": "commitment", "secret": secret }), None)["commitment"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// The acceptance criterion for computing commitments anywhere but the CLI:
    /// the same secret must yield the value `veilproof-commit` prints.
    #[test]
    fn commitment_matches_the_core() {
        let secret = Fr::from(7u64);
        assert_eq!(
            commitment_of(SECRET_7),
            to_hex(&crypto::leaf_commitment(secret))
        );
    }

    #[test]
    fn new_secret_is_seeded_and_consistent() {
        let first = call(json!({ "op": "new_secret", "seed": SEED }), None);
        let again = call(json!({ "op": "new_secret", "seed": SEED }), None);
        assert_eq!(first, again);
        let secret = first["secret"].as_str().unwrap();
        assert_ne!(secret, SEED);
        assert_eq!(first["commitment"].as_str().unwrap(), commitment_of(secret));
    }

    /// The root has to be the tree's, or an issuer publishes one no proof matches.
    #[test]
    fn root_matches_the_tree() {
        let commitment = commitment_of(SECRET_7);
        let answer = call(json!({ "op": "root", "leaves": [commitment] }), None);

        let mut tree = MerkleTree::new();
        tree.push(crypto::leaf_commitment(Fr::from(7u64))).unwrap();
        assert_eq!(answer["root"].as_str().unwrap(), to_hex(&tree.root()));
        assert_eq!(answer["capacity"], MerkleTree::CAPACITY);
    }

    /// With the same seed, this path produces the bytes the server's does. Those
    /// are pinned to what the contract accepts by `tests/round_trip.rs`.
    #[test]
    fn proof_is_byte_identical_to_the_core() {
        let keys = dev_keys();
        let leaf = crypto::leaf_commitment(Fr::from(7u64));
        let answer = call(
            json!({
                "op": "prove",
                "leaves": [to_hex(&leaf)],
                "secret": SECRET_7,
                "holder": HOLDER,
                "seed": SEED,
            }),
            Some(&keys),
        );

        let tree = MerkleTree::from_leaves(vec![leaf]).unwrap();
        let mut rng = rng_from(SEED).unwrap();
        let expected = crypto::prove(&keys, &tree, Fr::from(7u64), HOLDER, &mut rng).unwrap();
        assert_eq!(answer["proof"]["a"], hex::encode(expected.proof.a));
        assert_eq!(answer["proof"]["b"], hex::encode(expected.proof.b));
        assert_eq!(answer["proof"]["c"], hex::encode(expected.proof.c));
        assert_eq!(answer["root"], hex::encode(expected.root));
        assert_eq!(answer["nullifier"], hex::encode(expected.nullifier));
    }

    #[test]
    fn proving_needs_keys_and_membership() {
        let request = json!({
            "op": "prove",
            "leaves": [commitment_of(SECRET_7)],
            "secret": SECRET_7,
            "holder": HOLDER,
            "seed": SEED,
        });
        assert_eq!(
            call(request, None)["error"],
            "the proving keys are not loaded"
        );

        let keys = dev_keys();
        let outsider = call(
            json!({
                "op": "prove",
                "leaves": [commitment_of(SECRET_7)],
                "secret": SEED,
                "holder": HOLDER,
                "seed": SEED,
            }),
            Some(&keys),
        );
        assert_eq!(
            outsider["error"],
            "this secret's commitment is not in the tree"
        );
    }

    #[test]
    fn malformed_input_is_reported_not_reduced() {
        let error = |secret: &str| {
            call(json!({ "op": "commitment", "secret": secret }), None)["error"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert!(error("xyz").contains("64 characters"));
        assert!(error("07").contains("64 characters"));
        // All ones is above the field order; reducing it would hash a different value.
        assert!(error(&"f".repeat(64)).contains("not a valid field element"));

        assert!(handle("not json", None).contains("bad request"));
        assert!(handle(r#"{"op":"nope"}"#, None).contains("bad request"));
    }

    #[test]
    fn an_overfull_tree_is_refused() {
        let leaves = vec![commitment_of(SECRET_7); MerkleTree::CAPACITY + 1];
        let answer = call(json!({ "op": "root", "leaves": leaves }), None);
        assert_eq!(answer["error"], "the tree is full");
    }
}
