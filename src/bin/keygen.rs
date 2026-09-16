//! Generate a production Groth16 trusted setup for veilproof.
//!
//! Usage: `veilproof-keygen <output-dir>`
//!
//! Writes `pk.bin` (proving key, used by the server) and `vk.bin` (verifying
//! key) to the directory, and prints the verifying key in Soroban's byte
//! encoding so it can be handed to veilproof-registry's constructor.
//!
//! SECURITY: run this on a trusted machine with a good entropy source and
//! destroy the machine's state afterwards — the setup's toxic waste must not be
//! recoverable, or membership proofs can be forged. A multi-party ceremony is
//! stronger than single-party generation; see the README.

use std::path::PathBuf;

use veilproof_server::crypto;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: veilproof-keygen <output-dir>")?;
    let dir = PathBuf::from(dir);

    eprintln!("Generating a Groth16 setup with the OS secure RNG.");
    eprintln!("SECURITY: destroy this machine's state afterwards so the toxic");
    eprintln!("waste cannot be recovered. A multi-party ceremony is stronger.");

    let keys = crypto::generate_secure();
    keys.save(&dir)?;
    eprintln!("Wrote pk.bin and vk.bin to {}", dir.display());

    // The verifying key, for veilproof-registry's constructor.
    let vk = keys.encoded_vk();
    println!("# Verifying key (Soroban encoding) for veilproof-registry:");
    println!("alpha_g1 = {}", hex::encode(vk.alpha_g1));
    println!("beta_g2  = {}", hex::encode(vk.beta_g2));
    println!("gamma_g2 = {}", hex::encode(vk.gamma_g2));
    println!("delta_g2 = {}", hex::encode(vk.delta_g2));
    for (i, ic) in vk.ic.iter().enumerate() {
        println!("ic[{i}]   = {}", hex::encode(ic));
    }
    Ok(())
}
