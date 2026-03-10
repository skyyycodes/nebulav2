// RISC Zero Guest — runs inside the zkVM
// Proves: "I verified a valid Falcon-512 (FN-DSA, FIPS 206) signature over tx_bytes"
// Commits to journal: sha256(pubkey) || sha256(tx_bytes)  (64 bytes)

#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use falcon::{FnDsaSignature, DomainSeparation};

risc0_zkvm::guest::entry!(main);

#[derive(serde::Deserialize)]
struct Inputs {
    public_key: Vec<u8>,
    tx_bytes: Vec<u8>,
    signature: Vec<u8>,
}

fn main() {
    let inputs: Inputs = env::read();

    // Verify Falcon-512 signature — panics if invalid
    FnDsaSignature::verify(
        &inputs.signature,
        &inputs.public_key,
        &inputs.tx_bytes,
        &DomainSeparation::None,
    )
    .expect("Falcon-512 signature verification failed");

    // Commit public outputs: sha256(pubkey) || sha256(tx_bytes)
    let pubkey_hash: [u8; 32] = Sha256::digest(&inputs.public_key).into();
    let tx_hash: [u8; 32] = Sha256::digest(&inputs.tx_bytes).into();

    let mut journal = Vec::with_capacity(64);
    journal.extend_from_slice(&pubkey_hash);
    journal.extend_from_slice(&tx_hash);

    env::commit_slice(&journal);
}
