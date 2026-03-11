// RISC Zero Host — runs on your machine
// 1. Reads proof_inputs.json (written by sphincs.py)
// 2. Executes the guest in the zkVM
// 3. Generates a Groth16 proof via:
//    - Bonsai network: set BONSAI_API_KEY + BONSAI_API_URL (recommended)
//    - Boundless network: set BOUNDLESS_* env vars (feature = "boundless")
//    - Local dev mode: no env vars (STARK only, not Groth16)
// 4. Writes proof.json with seal + image_id + journal for Soroban

use std::fs;

use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use serde::{Deserialize, Serialize};
use sphincs_methods::{SPHINCS_GUEST_ELF, SPHINCS_GUEST_ID};

#[derive(Deserialize)]
struct ProofInputs {
    public_key: String, // hex
    tx_bytes: String,   // hex
    signature: String,  // hex
}

#[derive(Serialize)]
struct GuestInputs {
    public_key: Vec<u8>,
    tx_bytes: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct ProofOutput {
    /// Groth16 seal bytes — hex encoded
    seal: String,
    /// RISC Zero image ID — hex encoded
    image_id: String,
    /// Journal bytes committed by guest: sha256(pubkey) || sha256(tx) — hex
    journal: String,
    /// sha256(pubkey_bytes) — hex
    pubkey_hash: String,
    /// sha256(tx_bytes) — hex
    tx_hash: String,
}

fn image_id_hex() -> String {
    let words = SPHINCS_GUEST_ID;
    let mut bytes = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    hex::encode(bytes)
}

#[cfg(feature = "boundless")]
mod boundless_prove {
    use super::*;
    use anyhow::Result;
    use boundless_market::{
        storage::{StorageUploaderConfig, StorageUploaderType},
        Client,
    };
    use std::time::Duration;

    pub async fn prove_with_boundless(guest_inputs: &GuestInputs) -> Result<ProofOutput> {
        let rpc_url: url::Url = std::env::var("BOUNDLESS_RPC_URL")
            .expect("BOUNDLESS_RPC_URL must be set")
            .parse()?;
        let private_key = std::env::var("BOUNDLESS_PRIVATE_KEY")
            .expect("BOUNDLESS_PRIVATE_KEY must be set");

        println!("Connecting to Boundless network (Base Sepolia)...");

        // Serialise inputs using the same format risc0 env::read() expects
        let input_bytes = risc0_zkvm::serde::to_vec(guest_inputs)
            .map_err(|e| anyhow::anyhow!("serialisation failed: {e}"))?
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<u8>>();

        // Build Pinata storage config using builder (struct is #[non_exhaustive])
        let pinata_jwt = std::env::var("PINATA_JWT")
            .expect("PINATA_JWT must be set for Boundless uploads");

        let storage_config = StorageUploaderConfig::builder()
            .storage_uploader(StorageUploaderType::Pinata)
            .pinata_jwt(pinata_jwt)
            .build()
            .map_err(|e| anyhow::anyhow!("storage config error: {e}"))?;

        let client = Client::builder()
            .with_rpc_url(rpc_url)
            .with_private_key_str(&private_key)?
            .with_uploader_config(&storage_config)
            .await?
            .build()
            .await?;

        println!("Uploading guest ELF and submitting Groth16 proof request...");
        // Use max_price_per_mcycle — 500 gwei/Mcycle, well above market rate
        // Falcon-512 circuit is ~300-500 Mcycles → total ~150k-250k gwei
        let offer = boundless_market::request_builder::OfferParams::builder()
            .max_price_per_mcycle(boundless_market::alloy::primitives::U256::from(500_000_000_000u64))
            .build()?;
        let request = client
            .new_request()
            .with_program(SPHINCS_GUEST_ELF)
            .with_stdin(input_bytes)
            .with_groth16_proof()
            .with_offer(offer);

        let (request_id, expires_at) = client.submit(request).await?;
        println!("Request submitted: {} — waiting for fulfillment...", request_id);

        let fulfillment = client
            .wait_for_request_fulfillment(request_id, Duration::from_secs(15), expires_at)
            .await?;

        println!("Proof fulfilled by Boundless network.");

        // Decode journal from fulfillment data
        use boundless_market::contracts::FulfillmentData;
        let journal: Vec<u8> = match fulfillment.data()? {
            FulfillmentData::ImageIdAndJournal(_, j) => j.to_vec(),
            _ => anyhow::bail!("unexpected fulfillment data type"),
        };
        assert_eq!(journal.len(), 64, "unexpected journal length");

        let seal = hex::encode(&fulfillment.seal);
        let pubkey_hash = hex::encode(&journal[..32]);
        let tx_hash = hex::encode(&journal[32..]);

        Ok(ProofOutput {
            seal,
            image_id: image_id_hex(),
            journal: hex::encode(&journal),
            pubkey_hash,
            tx_hash,
        })
    }
}

/// Prove via Bonsai (RISC Zero hosted Groth16 network).
/// Requires BONSAI_API_KEY and BONSAI_API_URL env vars.
fn prove_bonsai(guest_inputs: &GuestInputs) -> ProofOutput {
    use std::time::Instant;

    println!("Bonsai mode: submitting Groth16 proof request to api.bonsai.xyz...");
    println!("Running zkVM guest (Falcon-512 / FN-DSA verification)...");

    let env = ExecutorEnv::builder()
        .write(guest_inputs)
        .expect("failed to serialize guest inputs")
        .build()
        .expect("failed to build executor env");

    let t0 = Instant::now();
    let prover = default_prover();

    println!("Waiting for Bonsai to generate Groth16 proof (typically 2-5 min)...");

    let receipt = prover
        .prove_with_opts(env, SPHINCS_GUEST_ELF, &ProverOpts::groth16())
        .expect("Bonsai proving failed")
        .receipt;

    println!("Proof done in {:.1}s", t0.elapsed().as_secs_f32());
    println!("Verifying receipt locally...");
    receipt.verify(SPHINCS_GUEST_ID).expect("receipt verification failed");
    println!("Receipt verified. ✓");

    let journal = receipt.journal.bytes.clone();
    assert_eq!(journal.len(), 64, "unexpected journal length");

    let pubkey_hash = hex::encode(&journal[..32]);
    let tx_hash = hex::encode(&journal[32..]);

    let seal = match receipt.inner.groth16() {
        Ok(g) => hex::encode(&g.seal),
        Err(e) => panic!("expected Groth16 seal from Bonsai but got: {e}"),
    };

    println!("  pubkey_hash: {pubkey_hash}");
    println!("  tx_hash:     {tx_hash}");
    println!("  seal_len:    {} bytes", hex::decode(&seal).unwrap().len());

    ProofOutput {
        seal,
        image_id: image_id_hex(),
        journal: hex::encode(&journal),
        pubkey_hash,
        tx_hash,
    }
}

/// Prove locally (STARK only — no Groth16, cannot be verified on-chain).
fn prove_local(guest_inputs: &GuestInputs) -> ProofOutput {
    use std::time::Instant;

    let env = ExecutorEnv::builder()
        .write(guest_inputs)
        .expect("failed to serialize guest inputs")
        .build()
        .expect("failed to build executor env");

    println!("Local mode (STARK, not Groth16 — for development only)");
    println!("Running zkVM guest (Falcon-512 / FN-DSA verification)...");
    println!();

    let t0 = Instant::now();
    std::env::set_var("RISC0_INFO", "1");

    let prover = default_prover();
    println!("[Step 1/3] STARK proof generation started...");
    println!("           (Falcon-512, ~7 min on CPU)");

    let t_prove = Instant::now();
    let receipt = prover
        .prove_with_opts(env, SPHINCS_GUEST_ELF, &ProverOpts::fast())
        .expect("proving failed")
        .receipt;

    println!("[Step 2/3] STARK proof done in {:.1}s", t_prove.elapsed().as_secs_f32());
    println!("[Step 3/3] Verifying receipt...");
    receipt.verify(SPHINCS_GUEST_ID).expect("receipt verification failed");
    println!("           Receipt verified. ✓  (total: {:.1}s)", t0.elapsed().as_secs_f32());

    let journal = receipt.journal.bytes.clone();
    assert_eq!(journal.len(), 64, "unexpected journal length");

    let pubkey_hash = hex::encode(&journal[..32]);
    let tx_hash = hex::encode(&journal[32..]);

    // Local mode has no Groth16 seal — store journal as placeholder
    let seal = match receipt.inner.groth16() {
        Ok(g) => hex::encode(&g.seal),
        Err(_) => {
            println!("Note: no Groth16 seal in local mode. Use Bonsai for on-chain proof.");
            hex::encode(&receipt.journal.bytes)
        }
    };

    ProofOutput {
        seal,
        image_id: image_id_hex(),
        journal: hex::encode(&journal),
        pubkey_hash,
        tx_hash,
    }
}

#[cfg(feature = "boundless")]
#[tokio::main]
async fn main() {
    let (_inputs_path, output_path, guest_inputs) = load_inputs();

    let output = if std::env::var("BONSAI_API_KEY").is_ok() {
        prove_bonsai(&guest_inputs)
    } else if std::env::var("BOUNDLESS_RPC_URL").is_ok() {
        boundless_prove::prove_with_boundless(&guest_inputs)
            .await
            .expect("Boundless proving failed")
    } else {
        prove_local(&guest_inputs)
    };

    write_output(&output_path, output);
}

#[cfg(not(feature = "boundless"))]
fn main() {
    let (_inputs_path, output_path, guest_inputs) = load_inputs();

    let output = if std::env::var("BONSAI_API_KEY").is_ok() {
        prove_bonsai(&guest_inputs)
    } else {
        prove_local(&guest_inputs)
    };

    write_output(&output_path, output);
}

fn load_inputs() -> (String, String, GuestInputs) {
    let inputs_path = std::env::args().nth(1).unwrap_or("proof_inputs.json".into());
    let output_path = std::env::args().nth(2).unwrap_or("proof.json".into());

    let raw = fs::read_to_string(&inputs_path)
        .unwrap_or_else(|_| panic!("cannot read {inputs_path}"));
    let inputs: ProofInputs = serde_json::from_str(&raw).expect("invalid proof_inputs.json");

    let guest_inputs = GuestInputs {
        public_key: hex::decode(&inputs.public_key).expect("bad pubkey hex"),
        tx_bytes: hex::decode(&inputs.tx_bytes).expect("bad tx hex"),
        signature: hex::decode(&inputs.signature).expect("bad sig hex"),
    };

    (inputs_path, output_path, guest_inputs)
}

fn write_output(output_path: &str, output: ProofOutput) {
    println!("  pubkey_hash: {}", output.pubkey_hash);
    println!("  tx_hash:     {}", output.tx_hash);
    fs::write(output_path, serde_json::to_string_pretty(&output).unwrap())
        .expect("failed to write output");
    println!("Proof written → {output_path}");
}
