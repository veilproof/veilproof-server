//! Print the verifying key of an existing trusted setup.
//!
//! Usage: `veilproof-vk <keys-dir>`
//!
//! `veilproof-keygen` prints the verifying key once, at generation time. This
//! prints it for keys already on disk, which is what you need to answer the
//! question that actually matters in an operational incident: *are the keys
//! this server is using the ones the on-chain circuit was registered with?*
//!
//! The digest it prints is the value to set as `VEILPROOF_VK_SHA256`, which
//! makes the server verify that for itself at boot.

use std::path::PathBuf;

use veilproof_server::crypto::Keys;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: veilproof-vk <keys-dir>")?;
    let keys = Keys::load(&PathBuf::from(dir))?;
    let vk = keys.encoded_vk();

    println!("# Verifying key (Soroban encoding) for veilproof-registry:");
    println!("alpha_g1 = {}", hex::encode(vk.alpha_g1));
    println!("beta_g2  = {}", hex::encode(vk.beta_g2));
    println!("gamma_g2 = {}", hex::encode(vk.gamma_g2));
    println!("delta_g2 = {}", hex::encode(vk.delta_g2));
    for (i, ic) in vk.ic.iter().enumerate() {
        println!("ic[{i}]   = {}", hex::encode(ic));
    }
    println!();
    println!("# Set this so the server checks its own setup at boot:");
    println!("VEILPROOF_VK_SHA256={}", hex::encode(keys.vk_digest()));
    Ok(())
}
