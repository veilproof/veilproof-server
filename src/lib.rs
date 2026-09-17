//! veilproof-server: Merkle-tree management and Groth16 membership-proof
//! generation for the veilproof-registry Soroban contract.
//!
//! The crypto module is the trust-critical core. See its docs and the
//! `tests/round_trip.rs` centerpiece test.

pub mod api;
pub mod crypto;
pub mod keysource;
pub mod merkle;
pub mod store;
