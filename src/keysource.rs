//! Where the trusted-setup keys come from at boot.
//!
//! Three sources, in order of precedence:
//!
//! 1. `VEILPROOF_KEYS_URL` — a base URL holding `pk.bin` and `vk.bin`, fetched
//!    at startup. This is the one that makes hosted deployment practical: the
//!    keys stay out of the image and out of git, and a platform needs nothing
//!    but an environment variable.
//! 2. `VEILPROOF_KEYS_DIR` — a directory on disk (a mounted volume locally).
//! 3. Neither — the deterministic development setup, which is **insecure**.
//!
//! A Groth16 proving key is public; only the setup's toxic waste must be
//! destroyed. So serving these over plain HTTPS is fine, and the risk worth
//! guarding against is not disclosure but **substitution**: keys that are not
//! the ones the on-chain circuit was registered with. Set
//! `VEILPROOF_VK_SHA256` to the expected verifying-key digest and the server
//! refuses to start on a mismatch, rather than running happily and producing
//! proofs the contract rejects.

use crate::crypto::{self, Keys};

/// Names kept together so the README, the deploy configs and the code cannot
/// drift apart silently.
pub const ENV_KEYS_URL: &str = "VEILPROOF_KEYS_URL";
pub const ENV_KEYS_DIR: &str = "VEILPROOF_KEYS_DIR";
pub const ENV_VK_SHA256: &str = "VEILPROOF_VK_SHA256";

#[derive(Debug, thiserror::Error)]
pub enum KeySourceError {
    #[error("failed to fetch {url}: {source}")]
    Fetch {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{url} returned HTTP {status}")]
    Status { url: String, status: u16 },
    #[error("could not read the trusted-setup keys: {0}")]
    Io(#[from] crypto::KeyIoError),
    #[error(
        "the verifying key does not match {ENV_VK_SHA256}.\n  expected: {expected}\n  actual:   {actual}\n\
         These are not the keys the on-chain circuit was registered with, so every proof \
         this server produced would be rejected. Refusing to start."
    )]
    VkMismatch { expected: String, actual: String },
    #[error("{ENV_VK_SHA256} must be 64 hex characters")]
    BadDigest,
}

/// Read an environment variable, treating empty or blank as unset.
///
/// Compose files and platform dashboards routinely pass a variable through as
/// `""` when it has no value. Taking that literally would make an unset
/// integrity pin look like a pin that can never match.
fn env_opt(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

/// Resolve and load the trusted setup according to the environment.
pub async fn load_from_env() -> Result<Keys, KeySourceError> {
    let keys = match (env_opt(ENV_KEYS_URL), env_opt(ENV_KEYS_DIR)) {
        (Some(url), _) => {
            let base = url.trim_end_matches('/');
            tracing::info!(url = base, "fetching trusted-setup keys");
            let pk = fetch(&format!("{base}/pk.bin")).await?;
            let vk = fetch(&format!("{base}/vk.bin")).await?;
            let keys = Keys::from_bytes(&pk, &vk)?;
            tracing::info!(url = base, "loaded trusted-setup keys over HTTP");
            keys
        }
        (None, Some(dir)) => {
            let keys = Keys::load(std::path::Path::new(&dir))?;
            tracing::info!(dir, "loaded trusted-setup keys from disk");
            keys
        }
        (None, None) => {
            tracing::warn!(
                "neither {ENV_KEYS_URL} nor {ENV_KEYS_DIR} is set — using the \
                 DEVELOPMENT trusted setup (deterministic, insecure). Do not use \
                 for anything of value; run veilproof-keygen. See the README."
            );
            crypto::dev_keys()
        }
    };

    match env_opt(ENV_VK_SHA256) {
        Some(expected) => {
            verify_digest(&keys, &expected)?;
            tracing::info!(digest = %expected, "verifying key matches {ENV_VK_SHA256}");
        }
        None => tracing::warn!(
            "{ENV_VK_SHA256} not set — the server cannot tell whether its trusted \
             setup is the one the on-chain circuit was registered with. Print the \
             expected digest with `veilproof-vk <keys-dir>`."
        ),
    }
    Ok(keys)
}

/// Check the loaded keys against a pinned verifying-key digest.
fn verify_digest(keys: &Keys, expected: &str) -> Result<(), KeySourceError> {
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeySourceError::BadDigest);
    }
    let actual = hex::encode(keys.vk_digest());
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(KeySourceError::VkMismatch {
            expected: expected.to_ascii_lowercase(),
            actual,
        });
    }
    Ok(())
}

async fn fetch(url: &str) -> Result<Vec<u8>, KeySourceError> {
    let res = reqwest::get(url)
        .await
        .map_err(|source| KeySourceError::Fetch {
            url: url.to_string(),
            source,
        })?;
    if !res.status().is_success() {
        return Err(KeySourceError::Status {
            url: url.to_string(),
            status: res.status().as_u16(),
        });
    }
    let bytes = res.bytes().await.map_err(|source| KeySourceError::Fetch {
        url: url.to_string(),
        source,
    })?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_digest_is_accepted() {
        let keys = crypto::dev_keys();
        let digest = hex::encode(keys.vk_digest());
        verify_digest(&keys, &digest).expect("the key's own digest must match");
        // Case is not significant — operators paste these from anywhere.
        verify_digest(&keys, &digest.to_uppercase()).expect("uppercase must match");
    }

    #[test]
    fn a_different_key_is_rejected() {
        let keys = crypto::dev_keys();
        let wrong = "00".repeat(32);
        let err = verify_digest(&keys, &wrong).unwrap_err();
        assert!(matches!(err, KeySourceError::VkMismatch { .. }));
    }

    #[test]
    fn a_malformed_digest_is_rejected_rather_than_ignored() {
        let keys = crypto::dev_keys();
        for bad in ["", "abc", &"zz".repeat(32), &"ab".repeat(31)] {
            assert!(
                matches!(
                    verify_digest(&keys, bad).unwrap_err(),
                    KeySourceError::BadDigest
                ),
                "{bad:?} should be rejected as malformed",
            );
        }
    }

    #[test]
    fn the_digest_is_stable_across_loads() {
        // The pin is only useful if the same setup always hashes the same way.
        let a = crypto::dev_keys();
        let mut pk = Vec::new();
        let mut vk = Vec::new();
        {
            use ark_serialize::CanonicalSerialize;
            a.pk.serialize_uncompressed(&mut pk).unwrap();
            a.vk.serialize_uncompressed(&mut vk).unwrap();
        }
        let b = Keys::from_bytes(&pk, &vk).unwrap();
        assert_eq!(a.vk_digest(), b.vk_digest());
    }
}
