//! Compute the leaf commitment for a holder secret.
//!
//! Usage: `veilproof-commit [<secret-hex>]`
//!
//! With no argument a fresh secret is generated with the OS secure RNG. The
//! secret is printed to stdout for the holder to keep; the commitment is what
//! they hand to the issuer to be added to the tree.
//!
//! This exists so a holder never has to send their secret anywhere to find out
//! what their commitment is: `leaf = H(secret, LEAF_DOMAIN)` is computed here,
//! locally. The issuer only ever learns the commitment.

use ark_bn254::Fr;
use ark_std::UniformRand;
use rand::rngs::OsRng;

use veilproof_server::crypto::{self, encoding::fr_be, encoding::fr_from_be};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (secret, generated) = match args.as_slice() {
        [] => (Fr::rand(&mut OsRng), true),
        [hex_secret] => (parse_secret(hex_secret)?, false),
        _ => return Err("usage: veilproof-commit [<secret-hex>]".into()),
    };

    let commitment = crypto::leaf_commitment(secret);

    if generated {
        eprintln!("Generated a new secret with the OS secure RNG.");
        eprintln!("Keep the secret private — anyone holding it can prove your");
        eprintln!("membership. Give the issuer only the commitment.");
    }
    println!("secret     = {}", hex::encode(fr_be(&secret)));
    println!("commitment = {}", hex::encode(fr_be(&commitment)));

    Ok(())
}

/// Parse a 32-byte big-endian secret, the same encoding the API accepts.
fn parse_secret(s: &str) -> Result<Fr, Box<dyn std::error::Error>> {
    let bytes = hex::decode(s.trim()).map_err(|_| "the secret must be hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "the secret must be 32 bytes (64 hex chars)")?;
    Ok(fr_from_be(&arr))
}
