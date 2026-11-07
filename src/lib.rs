//! veilproof-server: Merkle-tree management and Groth16 membership-proof
//! generation for the veilproof-registry Soroban contract.
//!
//! The crypto module is the trust-critical core. See its docs and the
//! `tests/round_trip.rs` centerpiece test. It and the Merkle tree build without
//! the `server` feature, which is how `prover/` runs the same code in a browser.

#[cfg(feature = "server")]
pub mod api;
pub mod crypto;
#[cfg(feature = "server")]
pub mod keysource;
pub mod merkle;
#[cfg(feature = "server")]
pub mod store;
