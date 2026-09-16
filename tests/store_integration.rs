//! Integration tests for the Postgres store and its interaction with the
//! crypto core. These need a real database and are skipped when `DATABASE_URL`
//! is unset, so `cargo test` without a database still passes; CI provides a
//! Postgres service so they run there.

use ark_bn254::Fr;
use rand::rngs::OsRng;
use veilproof_server::crypto::{self, encoding};
use veilproof_server::merkle::MerkleTree;
use veilproof_server::store::Store;

/// A per-run unique issuer name so repeated CI runs against the same database
/// don't collide.
fn unique_issuer(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

async fn store_or_skip() -> Option<Store> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(Store::connect(&url).await.expect("connect + migrate"))
}

#[tokio::test]
async fn add_publish_read_and_prove() {
    let Some(store) = store_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    let issuer = unique_issuer("kyc");
    let secret = Fr::from(555_000_111u64);

    // The holder's commitment plus a couple of others.
    let (pos, count) = store
        .add_leaf(&issuer, crypto::leaf_commitment(secret))
        .await
        .unwrap();
    assert_eq!(pos, 0);
    assert_eq!(count, 1);
    store.add_leaf(&issuer, Fr::from(7u64)).await.unwrap();
    store.add_leaf(&issuer, Fr::from(8u64)).await.unwrap();

    // Reads.
    assert!(store.issuer_exists(&issuer).await.unwrap());
    assert_eq!(store.leaf_count(&issuer).await.unwrap(), 3);
    assert!(store.list_issuers().await.unwrap().contains(&issuer));

    // Publish, then confirm the stored root round-trips.
    let tree = MerkleTree::from_leaves(store.leaves(&issuer).await.unwrap()).unwrap();
    store
        .set_published_root(&issuer, tree.root())
        .await
        .unwrap();
    assert_eq!(
        store.published_root(&issuer).await.unwrap(),
        Some(tree.root())
    );

    // Prove against the stored tree — the full store → crypto path.
    let keys = crypto::dev_keys();
    let rebuilt = MerkleTree::from_leaves(store.leaves(&issuer).await.unwrap()).unwrap();
    let holder = "GBYNOOC3UUF2QBCNIRUEHK2J3JOCDSV2QTLG445GW5ZEENPYDSU33OFQ";
    let mp = crypto::prove(&keys, &rebuilt, secret, holder, &mut OsRng).unwrap();
    assert_eq!(mp.root, encoding::fr_be(&rebuilt.root()));
    assert_eq!(mp.nullifier, encoding::fr_be(&crypto::nullifier(secret)));
}

#[tokio::test]
async fn non_member_secret_is_rejected() {
    let Some(store) = store_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let issuer = unique_issuer("kyc-nonmember");
    store.add_leaf(&issuer, Fr::from(1u64)).await.unwrap();
    store.add_leaf(&issuer, Fr::from(2u64)).await.unwrap();

    let keys = crypto::dev_keys();
    let tree = MerkleTree::from_leaves(store.leaves(&issuer).await.unwrap()).unwrap();
    let outsider = Fr::from(999_999u64);
    let holder = "GBYNOOC3UUF2QBCNIRUEHK2J3JOCDSV2QTLG445GW5ZEENPYDSU33OFQ";
    let res = crypto::prove(&keys, &tree, outsider, holder, &mut OsRng);
    assert_eq!(res, Err(crypto::CryptoError::NotAMember));
}
