//! Submit XMSS proof to Sindri SP1 and poll for result.
//!
//! Usage: submit --inputs proof_inputs.json --api-key <key> [--circuit-id <id>]
//!
//! Flow:
//!   1. If no --circuit-id: upload the SP1 program zip and compile it
//!   2. Submit proof request with stdin (pk, tx, sig as JSON)
//!   3. Poll until done, write proof.json

use std::path::PathBuf;
use std::time::Duration;
use std::thread;

use serde::{Deserialize, Serialize};

const SINDRI_API: &str = "https://sindri.app/api/v1";
const POLL_INTERVAL: u64 = 5; // seconds

#[derive(Deserialize)]
struct ProofInputs {
    public_key: String,
    tx_bytes: String,
    signature: String,
    leaf_index: u32,
}

#[derive(Serialize)]
struct GuestInput {
    public_key: Vec<u8>,
    tx_bytes: Vec<u8>,
    signature: Vec<u8>,
}

fn get_flag(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let inputs_path = get_flag(&args, "--inputs").unwrap_or_else(|| "proof_inputs.json".into());
    let api_key = get_flag(&args, "--api-key")
        .or_else(|| std::env::var("SINDRI_API_KEY").ok())
        .expect("--api-key or SINDRI_API_KEY required");
    let circuit_id = get_flag(&args, "--circuit-id");

    let raw = std::fs::read_to_string(&inputs_path)
        .unwrap_or_else(|_| panic!("cannot read {inputs_path}"));
    let inputs: ProofInputs = serde_json::from_str(&raw).expect("invalid proof_inputs.json");

    let pk_bytes = hex::decode(&inputs.public_key).expect("bad public_key");
    let tx_bytes = hex::decode(&inputs.tx_bytes).expect("bad tx_bytes");
    let sig_bytes = hex::decode(&inputs.signature).expect("bad signature");

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .unwrap();

    // Step 1: get or upload circuit
    let circuit_id = if let Some(id) = circuit_id {
        println!("Using existing circuit: {id}");
        id
    } else {
        upload_circuit(&client, &api_key)
    };

    // Step 2: wait for circuit to be ready
    wait_for_circuit(&client, &api_key, &circuit_id);

    // Step 3: submit proof
    let proof_id = submit_proof(&client, &api_key, &circuit_id, &pk_bytes, &tx_bytes, &sig_bytes);
    println!("Proof job submitted: {proof_id}");

    // Step 4: poll for result
    let proof = poll_proof(&client, &api_key, &proof_id);
    println!("Proof complete!");

    std::fs::write("proof.json", serde_json::to_string_pretty(&proof).unwrap())
        .expect("failed to write proof.json");
    println!("Proof written → proof.json");
}

fn upload_circuit(client: &reqwest::blocking::Client, api_key: &str) -> String {
    println!("Uploading SP1 circuit to Sindri...");

    // The circuit zip must be pre-built. Look for it next to this binary.
    let zip_path = PathBuf::from("sp1_program.zip");
    if !zip_path.exists() {
        eprintln!("ERROR: sp1_program.zip not found.");
        eprintln!("Build it first with: cd sp1/program && zip -r ../../sp1_program.zip . -x target/*");
        std::process::exit(1);
    }

    let zip_bytes = std::fs::read(&zip_path).expect("cannot read sp1_program.zip");
    let part = reqwest::blocking::multipart::Part::bytes(zip_bytes)
        .file_name("sp1_program.zip")
        .mime_str("application/zip")
        .unwrap();
    let form = reqwest::blocking::multipart::Form::new().part("files", part);

    let resp: serde_json::Value = client
        .post(format!("{SINDRI_API}/circuit/create"))
        .header("Authorization", format!("Bearer {api_key}"))
        .multipart(form)
        .send()
        .expect("upload request failed")
        .json()
        .expect("invalid JSON response");

    if let Some(err) = resp.get("error") {
        panic!("Circuit upload failed: {}", resp["message"].as_str().unwrap_or(&err.to_string()));
    }

    let id = resp["circuit_id"].as_str().expect("no circuit_id in response").to_string();
    println!("Circuit uploaded: {id}");
    id
}

fn wait_for_circuit(client: &reqwest::blocking::Client, api_key: &str, circuit_id: &str) {
    print!("Waiting for circuit compilation");
    loop {
        let resp: serde_json::Value = client
            .get(format!("{SINDRI_API}/circuit/{circuit_id}/detail"))
            .header("Authorization", format!("Bearer {api_key}"))
            .send()
            .expect("status request failed")
            .json()
            .expect("invalid JSON");

        let status = resp["status"].as_str().unwrap_or("unknown");
        match status {
            "Ready" => { println!(" done!"); return; }
            "Failed" => panic!("Circuit compilation failed: {}", resp["error"].as_str().unwrap_or("unknown error")),
            _ => { print!("."); let _ = std::io::Write::flush(&mut std::io::stdout()); }
        }
        thread::sleep(Duration::from_secs(POLL_INTERVAL));
    }
}

fn submit_proof(
    client: &reqwest::blocking::Client,
    api_key: &str,
    circuit_id: &str,
    pk: &[u8],
    tx: &[u8],
    sig: &[u8],
) -> String {
    // SP1 stdin: three Vec<u8> values serialized as hex arrays in proof_input JSON
    let proof_input = serde_json::json!({
        "stdin": [
            hex::encode(pk),
            hex::encode(tx),
            hex::encode(sig)
        ]
    });

    let resp: serde_json::Value = client
        .post(format!("{SINDRI_API}/circuit/{circuit_id}/prove"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&proof_input)
        .send()
        .expect("prove request failed")
        .json()
        .expect("invalid JSON response");

    if let Some(err) = resp.get("error") {
        panic!("Proof submission failed: {}", resp["message"].as_str().unwrap_or(&err.to_string()));
    }

    resp["proof_id"].as_str().expect("no proof_id in response").to_string()
}

fn poll_proof(client: &reqwest::blocking::Client, api_key: &str, proof_id: &str) -> serde_json::Value {
    print!("Proving");
    loop {
        let resp: serde_json::Value = client
            .get(format!("{SINDRI_API}/proof/{proof_id}/detail"))
            .header("Authorization", format!("Bearer {api_key}"))
            .send()
            .expect("poll request failed")
            .json()
            .expect("invalid JSON");

        let status = resp["status"].as_str().unwrap_or("unknown");
        match status {
            "Ready" => { println!(" done!"); return resp; }
            "Failed" => panic!("Proving failed: {}", resp.get("error").unwrap_or(&serde_json::Value::Null)),
            _ => { print!("."); let _ = std::io::Write::flush(&mut std::io::stdout()); }
        }
        thread::sleep(Duration::from_secs(POLL_INTERVAL));
    }
}
