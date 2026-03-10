// Falcon-512 (FN-DSA, FIPS 206) keygen + sign utility
// Usage: keygen [tx_bytes_hex] [output_path]
//   tx_bytes_hex: hex-encoded transaction bytes to sign (default: reads from proof_inputs_tx.hex)
//   output_path: where to write proof_inputs.json (default: proof_inputs.json)
//
// Outputs proof_inputs.json with { public_key, tx_bytes, signature } (all hex)

use falcon::{FnDsaKeyPair, DomainSeparation, FnDsaSignature};
use std::fs;

fn main() {
    let tx_hex_arg = std::env::args().nth(1);
    let output_path = std::env::args().nth(2).unwrap_or("proof_inputs.json".into());

    // Get tx bytes — from arg, from file, or use a default test message
    let tx_bytes: Vec<u8> = if let Some(hex) = tx_hex_arg {
        hex::decode(hex.trim()).expect("invalid tx hex argument")
    } else if let Ok(contents) = fs::read_to_string("tx_bytes.hex") {
        hex::decode(contents.trim()).expect("invalid tx_bytes.hex contents")
    } else {
        // Default test: sign a fixed message
        b"NEBULA-TEST-TX-v1".to_vec()
    };

    println!("Generating Falcon-512 keypair...");
    let kp = FnDsaKeyPair::generate(9).expect("keygen failed");

    let pk = kp.public_key().to_vec();
    let sk = kp.private_key().to_vec();

    println!("Public key  ({} bytes): {}...", pk.len(), &hex::encode(&pk)[..48]);
    println!("Private key ({} bytes): {}...", sk.len(), &hex::encode(&sk)[..48]);
    println!("TX bytes    ({} bytes): {}...", tx_bytes.len(), &hex::encode(&tx_bytes)[..std::cmp::min(48, hex::encode(&tx_bytes).len())]);

    println!("Signing...");
    let sig = kp.sign(&tx_bytes, &DomainSeparation::None)
        .expect("signing failed");
    let sig_bytes = sig.to_bytes().to_vec();
    println!("Signature   ({} bytes): {}...", sig_bytes.len(), &hex::encode(&sig_bytes)[..48]);

    // Verify locally before writing
    FnDsaSignature::verify(&sig_bytes, &pk, &tx_bytes, &DomainSeparation::None)
        .expect("local verification failed — bug in keygen");
    println!("Local verification: PASS");

    let data = serde_json::json!({
        "public_key": hex::encode(&pk),
        "tx_bytes": hex::encode(&tx_bytes),
        "signature": hex::encode(&sig_bytes),
        "algorithm": "Falcon-512"
    });

    fs::write(&output_path, serde_json::to_string_pretty(&data).unwrap())
        .expect("failed to write output");
    println!("Exported proof inputs → {output_path}");
}
