//! Postgres persistence.
//!
//! Stores leaf commitments (hashes issuers compute off-chain) and light
//! server-side bookkeeping. It never stores raw PII or holder secrets — a
//! holder's secret is used transiently to build a proof and is never written
//! anywhere. The veilproof-registry contract is the source of truth for
//! on-chain state; this is a convenience cache for tree management and UX.

use ark_bn254::Fr;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::crypto::encoding::{fr_be, fr_from_be};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("a stored value was not valid 32-byte hex")]
    BadHex,
    #[error("the tree for this issuer is full")]
    Full,
}

/// Wraps the connection pool and the schema operations the API needs.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

/// Maximum leaves per tree, mirroring the circuit's fixed depth.
const CAPACITY: usize = crate::merkle::MerkleTree::CAPACITY;

fn to_hex(f: &Fr) -> String {
    hex::encode(fr_be(f))
}

fn from_hex(s: &str) -> Result<Fr, StoreError> {
    let bytes = hex::decode(s).map_err(|_| StoreError::BadHex)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| StoreError::BadHex)?;
    Ok(fr_from_be(&arr))
}

impl Store {
    /// Connect and run migrations.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Health probe: a trivial query proving the connection is live.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    async fn ensure_issuer(&self, name: &str) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO issuers (name) VALUES ($1) ON CONFLICT (name) DO NOTHING")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Append a leaf commitment to the issuer's tree, returning its position
    /// and the new leaf count.
    pub async fn add_leaf(
        &self,
        issuer: &str,
        commitment: Fr,
    ) -> Result<(usize, usize), StoreError> {
        self.ensure_issuer(issuer).await?;
        let mut tx = self.pool.begin().await?;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM leaves WHERE issuer_name = $1")
            .bind(issuer)
            .fetch_one(&mut *tx)
            .await?;
        if count as usize >= CAPACITY {
            return Err(StoreError::Full);
        }
        let position = count as i32;
        sqlx::query("INSERT INTO leaves (issuer_name, position, commitment) VALUES ($1, $2, $3)")
            .bind(issuer)
            .bind(position)
            .bind(to_hex(&commitment))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok((position as usize, count as usize + 1))
    }

    /// All leaf commitments for an issuer, ordered by position.
    pub async fn leaves(&self, issuer: &str) -> Result<Vec<Fr>, StoreError> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT commitment FROM leaves WHERE issuer_name = $1 ORDER BY position ASC",
        )
        .bind(issuer)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|s| from_hex(s)).collect()
    }

    /// Record the published root for an issuer (creating the issuer if needed).
    pub async fn set_published_root(&self, issuer: &str, root: Fr) -> Result<(), StoreError> {
        self.ensure_issuer(issuer).await?;
        sqlx::query("UPDATE issuers SET published_root = $2 WHERE name = $1")
            .bind(issuer)
            .bind(to_hex(&root))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The issuer's last published root, if any.
    pub async fn published_root(&self, issuer: &str) -> Result<Option<Fr>, StoreError> {
        let row: Option<Option<String>> =
            sqlx::query_scalar("SELECT published_root FROM issuers WHERE name = $1")
                .bind(issuer)
                .fetch_optional(&self.pool)
                .await?;
        match row.flatten() {
            Some(s) => Ok(Some(from_hex(&s)?)),
            None => Ok(None),
        }
    }

    /// Note that a proof was generated for this nullifier (bookkeeping only).
    pub async fn record_nullifier(&self, issuer: &str, nullifier: Fr) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO generated_nullifiers (issuer_name, nullifier) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(issuer)
        .bind(to_hex(&nullifier))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
