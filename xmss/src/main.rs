/// XMSS-SHA2_10_256 keygen + sign tool
///
/// Subcommands:
///   xmss keygen --out key.json
///   xmss sign   --key key.json --tx <hex> --nonce <u32> --out proof_inputs.json
///   xmss verify --key key.json --inputs proof_inputs.json
///
/// key.json format:
///   { "public_key": hex, "secret_key": hex, "next_index": u32 }
///
/// proof_inputs.json format (fed into Noir Prover.toml):
///   {
///     "public_key":  hex(68 bytes),
///     "tx_bytes":    hex,
///     "signature":   hex(2500 bytes),   // full detached sig including idx + rand + wots + auth
///     "leaf_index":  u32,
///     "nonce":       u32,               // == leaf_index, written into journal
///   }

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use xmss::{KeyPair, SigningKey, VerifyingKey, XmssSha2_10_256, DetachedSignature};

// ── Key file ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct KeyFile {
    algorithm: String,
    public_key: String,  // hex
    secret_key: String,  // hex
    next_index: u32,
}

// ── Proof inputs (written for Noir) ──────────────────────────────────────────

#[derive(Serialize)]
struct ProofInputs {
    algorithm: String,
    public_key: String,   // hex(68 bytes)
    tx_bytes: String,     // hex
    signature: String,    // hex(2500 bytes) — detached sig
    leaf_index: u32,
    nonce: u32,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ── keygen ────────────────────────────────────────────────────────────────────

fn cmd_keygen(out: &PathBuf) {
    println!("Generating XMSS-SHA2_10_256 keypair (h=10, 1024 one-time keys)...");
    let mut rng = rand::rng();
    let mut kp = KeyPair::<XmssSha2_10_256>::generate(&mut rng)
        .expect("XMSS keygen failed");

    let sk_bytes = kp.signing_key().as_ref().to_vec();
    let pk_bytes = kp.verifying_key().as_ref().to_vec();

    let key_file = KeyFile {
        algorithm: "XMSS-SHA2_10_256".into(),
        public_key: hex::encode(&pk_bytes),
        secret_key: hex::encode(&sk_bytes),
        next_index: 0,
    };

    std::fs::write(out, serde_json::to_string_pretty(&key_file).unwrap())
        .expect("failed to write key file");

    println!("Public key ({} bytes): {}...", pk_bytes.len(), &hex::encode(&pk_bytes)[..16]);
    println!("Secret key ({} bytes): [hidden]", sk_bytes.len());
    println!("sha256(pubkey): {}", sha256_hex(&pk_bytes));
    println!("Key written → {}", out.display());
    println!("\nWARNING: Never reuse a key index. next_index is tracked in key.json.");
}

// ── sign ──────────────────────────────────────────────────────────────────────

fn cmd_sign(key_path: &PathBuf, tx_hex: &str, out: &PathBuf) {
    // Load key file
    let key_json = std::fs::read_to_string(key_path)
        .unwrap_or_else(|_| panic!("cannot read {}", key_path.display()));
    let mut key_file: KeyFile = serde_json::from_str(&key_json)
        .expect("invalid key.json");

    let sk_bytes = hex::decode(&key_file.secret_key).expect("bad secret_key hex");
    let pk_bytes = hex::decode(&key_file.public_key).expect("bad public_key hex");
    let tx_bytes = hex::decode(tx_hex).expect("bad tx hex");

    let leaf_index = key_file.next_index;
    println!("Signing with XMSS-SHA2_10_256, leaf_index={leaf_index}");

    // Reconstruct signing key
    let mut sk = SigningKey::<XmssSha2_10_256>::try_from(sk_bytes.as_slice())
        .expect("invalid signing key bytes");

    // Sign
    let detached_sig: DetachedSignature<XmssSha2_10_256> = sk
        .sign_detached(&tx_bytes)
        .expect("XMSS signing failed");

    let sig_bytes: &[u8] = detached_sig.as_ref();
    println!("Signature: {} bytes", sig_bytes.len());

    // Verify locally before writing
    let vk = VerifyingKey::<XmssSha2_10_256>::try_from(pk_bytes.as_slice())
        .expect("invalid verifying key bytes");
    vk.verify_detached(&detached_sig, &tx_bytes)
        .expect("local verification failed — something is wrong");
    println!("Local verification: OK");

    // Update key file with new SK state (index advanced) and next_index
    key_file.secret_key = hex::encode(sk.as_ref());
    key_file.next_index = leaf_index + 1;
    std::fs::write(key_path, serde_json::to_string_pretty(&key_file).unwrap())
        .expect("failed to update key file");

    // Write proof_inputs.json
    let inputs = ProofInputs {
        algorithm: "XMSS-SHA2_10_256".into(),
        public_key: hex::encode(&pk_bytes),
        tx_bytes: hex::encode(&tx_bytes),
        signature: hex::encode(sig_bytes),
        leaf_index,
        nonce: leaf_index,
    };

    std::fs::write(out, serde_json::to_string_pretty(&inputs).unwrap())
        .expect("failed to write proof_inputs.json");

    println!("pubkey_hash : {}", sha256_hex(&pk_bytes));
    println!("tx_hash     : {}", sha256_hex(&tx_bytes));
    println!("nonce       : {leaf_index}");
    println!("Proof inputs written → {}", out.display());
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(inputs_path: &PathBuf) {
    #[derive(Deserialize)]
    struct Inputs {
        public_key: String,
        tx_bytes: String,
        signature: String,
    }

    let raw = std::fs::read_to_string(inputs_path)
        .unwrap_or_else(|_| panic!("cannot read {}", inputs_path.display()));
    let inputs: Inputs = serde_json::from_str(&raw).expect("invalid proof_inputs.json");

    let pk_bytes = hex::decode(&inputs.public_key).expect("bad public_key hex");
    let tx_bytes = hex::decode(&inputs.tx_bytes).expect("bad tx_bytes hex");
    let sig_bytes = hex::decode(&inputs.signature).expect("bad signature hex");

    let vk = VerifyingKey::<XmssSha2_10_256>::try_from(pk_bytes.as_slice())
        .expect("invalid verifying key");
    let sig = DetachedSignature::<XmssSha2_10_256>::try_from(sig_bytes.as_slice())
        .expect("invalid signature bytes");

    vk.verify_detached(&sig, &tx_bytes)
        .expect("XMSS verification FAILED");

    println!("XMSS-SHA2_10_256 verification: OK");
    println!("pubkey_hash: {}", sha256_hex(&pk_bytes));
    println!("tx_hash    : {}", sha256_hex(&tx_bytes));
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("keygen") => {
            let out = get_flag(&args, "--out").unwrap_or("key.json");
            cmd_keygen(&PathBuf::from(out));
        }
        Some("sign") => {
            let key = get_flag(&args, "--key").expect("--key required");
            let tx = get_flag(&args, "--tx").expect("--tx <hex> required");
            let out = get_flag(&args, "--out").unwrap_or("proof_inputs.json");
            cmd_sign(&PathBuf::from(key), tx, &PathBuf::from(out));
        }
        Some("verify") => {
            let inputs = get_flag(&args, "--inputs").unwrap_or("proof_inputs.json");
            cmd_verify(&PathBuf::from(inputs));
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  xmss keygen [--out key.json]");
            eprintln!("  xmss sign --key key.json --tx <hex> [--out proof_inputs.json]");
            eprintln!("  xmss verify [--inputs proof_inputs.json]");
            std::process::exit(1);
        }
    }
}

fn get_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}
