//! nebula — XMSS Post-Quantum Wallet CLI
//!
//! Commands:
//!   nebula wallet create   — register a new wallet (XMSS pubkey → contract)
//!   nebula wallet info     — show balance and nonce for a pubkey_hash
//!   nebula fund            — deposit XLM into your wallet
//!   nebula intent          — show the tx_bytes you need to sign for a withdrawal
//!   nebula withdraw        — full flow: sign → prove → submit withdrawal on-chain
//!   nebula prove           — generate/poll a proof (without submitting)
//!   nebula submit          — submit a cached proof to the chain
//!   nebula ui              — interactive TUI dashboard
//!
//! Config is read from .env in the project root (two levels up from cli/).

mod tui;

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    str,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "nebula",
    about = "XMSS Post-Quantum Wallet on Stellar",
    version,
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Wallet management
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// Deposit XLM into your XMSS wallet
    Fund {
        /// Amount in stroops (1 XLM = 10_000_000)
        #[arg(long)]
        amount: i64,
        /// Recipient wallet ID (pubkey_hash hex, 64 chars). Defaults to your own wallet.
        #[arg(long)]
        to: Option<String>,
        /// Source Stellar account alias or key (default: from STELLAR_ACCOUNT env)
        #[arg(long)]
        from: Option<String>,
    },
    /// Show the message you must sign for a withdrawal
    Intent {
        /// Destination Stellar address (G...)
        #[arg(long)]
        destination: String,
        /// Amount in stroops
        #[arg(long)]
        amount: i64,
    },
    /// Full withdrawal: sign → prove → submit
    Withdraw {
        /// Destination Stellar address (G...)
        #[arg(long)]
        destination: String,
        /// Amount in stroops
        #[arg(long)]
        amount: i64,
        /// Skip signing step (use existing proof_inputs.json)
        #[arg(long)]
        skip_sign: bool,
        /// Skip proving step (use cached groth16_proof.json)
        #[arg(long)]
        skip_prove: bool,
        /// Use an existing Sindri proof ID
        #[arg(long)]
        proof_id: Option<String>,
    },
    /// Generate a ZK proof for a pending withdrawal (does not submit)
    Prove {
        /// Use an existing Sindri proof ID (skips submission, just polls)
        #[arg(long)]
        proof_id: Option<String>,
    },
    /// Submit a cached proof to complete a withdrawal
    Submit {
        /// Destination Stellar address (G...)
        #[arg(long)]
        destination: String,
        /// Amount in stroops
        #[arg(long)]
        amount: i64,
    },
    /// Interactive TUI dashboard
    Ui,
}

#[derive(Subcommand)]
enum WalletAction {
    /// Create a new XMSS keypair and show your wallet address (pubkey_hash)
    Create {
        /// Path to write key file (default: key.json in project root)
        #[arg(long)]
        key_out: Option<PathBuf>,
    },
    /// Show wallet balance and nonce
    Info {
        /// pubkey_hash hex (default: derived from key.json)
        #[arg(long)]
        pubkey_hash: Option<String>,
    },
}

// ── Config ────────────────────────────────────────────────────────────────────

struct Config {
    project_root:      PathBuf,
    wallet_contract:   String,
    contract_hash:     [u8; 32],
    sindri_api_key:    String,
    stellar_account:   String,
    key_file:          PathBuf,
    proof_inputs:      PathBuf,
    proof_cache:       PathBuf,
    xmss_bin:          PathBuf,
}

impl Config {
    fn load() -> Result<Self> {
        // Find project root (parent of cli/)
        // When running via cargo run: cwd is cli/
        // When installed: doesn't matter, use env var
        let cwd = env::current_dir()?;
        // Walk up to find the dir containing bridge.py or .env
        let root = find_project_root(&cwd)
            .unwrap_or_else(|| cwd.parent().unwrap_or(&cwd).to_path_buf());

        load_dotenv(&root.join(".env"));

        // Fall back to values baked in at compile time (from GitHub secrets via RUSTFLAGS/build.rs).
        const BAKED_CONTRACT_ID:   &str = env!("NEBULA_WALLET_CONTRACT_ID",   "NEBULA_WALLET_CONTRACT_ID not set at compile time");
        const BAKED_CONTRACT_HASH: &str = env!("NEBULA_WALLET_CONTRACT_HASH", "NEBULA_WALLET_CONTRACT_HASH not set at compile time");
        const BAKED_SINDRI_KEY:    &str = env!("NEBULA_SINDRI_API_KEY",       "NEBULA_SINDRI_API_KEY not set at compile time");

        let wallet_contract = env::var("WALLET_CONTRACT_ID")
            .unwrap_or_else(|_| BAKED_CONTRACT_ID.to_string());
        let contract_hash_hex = env::var("WALLET_CONTRACT_HASH")
            .unwrap_or_else(|_| BAKED_CONTRACT_HASH.to_string());
        let contract_hash = hex_to_32(&contract_hash_hex)
            .context("WALLET_CONTRACT_HASH must be 64 hex chars")?;
        let sindri_api_key = env::var("SINDRI_API_KEY")
            .unwrap_or_else(|_| BAKED_SINDRI_KEY.to_string());
        let stellar_account = env::var("STELLAR_ACCOUNT")
            .unwrap_or_else(|_| "quantum-deployer".into());

        let key_file     = root.join("key.json");
        let proof_inputs = root.join("proof_inputs.json");
        let proof_cache  = root.join("groth16_proof.json");

        // xmss binary: look in xmss/target/release/xmss
        let xmss_bin = root.join("xmss").join("target").join("release").join("xmss");

        Ok(Config {
            project_root: root,
            wallet_contract,
            contract_hash,
            sindri_api_key,
            stellar_account,
            key_file,
            proof_inputs,
            proof_cache,
            xmss_bin,
        })
    }
}

fn find_project_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("bridge.py").exists() || dir.join(".env").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn load_dotenv(path: &Path) {
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some((k, v)) = line.split_once('=') {
                env::set_var(k.trim(), v.trim());
            }
        }
    }
}

fn env_require(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("{key} not set in .env"))
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s)?;
    b.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

// ── Key file ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct KeyFile {
    algorithm: String,
    public_key: String,
    secret_key: String,
    next_index: u32,
}

impl KeyFile {
    fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_str(&text).context("invalid key.json")
    }

    fn pubkey_hash(&self) -> Result<[u8; 32]> {
        let pk = hex::decode(&self.public_key)?;
        Ok(Sha256::digest(&pk).into())
    }
}

// ── Proof inputs / cache ──────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
struct ProofInputs {
    public_key: String,
    tx_bytes: String,
    signature: String,
    leaf_index: u32,
    nonce: u32,
}

#[derive(Deserialize, Serialize)]
struct ProofCache {
    proof_id: String,
    proof_bytes: String,
    public_values: String,
    program_vkey: String,
    pubkey_hash: String,
    tx_hash: String,
    nonce: u32,
    destination: String,
    amount: i64,
}

// ── Stellar helpers ───────────────────────────────────────────────────────────

/// Decode a Stellar strkey (G... or C...) to its 32-byte payload.
fn stellar_to_raw(addr: &str) -> Result<[u8; 32]> {
    // Stellar uses RFC 4648 base32 with uppercase
    // pad to multiple of 8
    let pad = (8 - addr.len() % 8) % 8;
    let padded = format!("{addr}{}", "=".repeat(pad));
    let decoded = base32_decode(&padded)?;
    // decoded[0] = version, decoded[1..-2] = payload, decoded[-2..] = checksum
    let payload: [u8; 32] = decoded[1..decoded.len()-2]
        .try_into()
        .context("expected 32-byte payload")?;
    Ok(payload)
}

fn base32_decode(s: &str) -> Result<Vec<u8>> {
    // RFC 4648 base32 alphabet
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u64;
    let mut bit_count = 0i32;
    let mut out = Vec::new();
    for ch in s.chars() {
        if ch == '=' { break; }
        let val = ALPHABET.iter().position(|&b| b == ch as u8)
            .with_context(|| format!("invalid base32 char: {ch}"))? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8 & 0xff);
        }
    }
    Ok(out)
}

/// What the Soroban contract computes for Address::to_xdr(env).slice(4..36)
///
/// Address::to_xdr() returns ScVal XDR:
///   Contract C...: [SCV_ADDRESS(4)][SC_ADDRESS_TYPE_CONTRACT=1(4)][hash(32)] = 40B
///     slice(4..36) = [00000001][hash[0..28]] (28 bytes of hash, 4-byte discriminant prefix)
///   Account  G...: [SCV_ADDRESS(4)][SC_ADDRESS_TYPE_ACCOUNT=0(4)][KEY_ED25519=0(4)][key(32)] = 44B
///     slice(4..36) = [00000000][00000000][key[0..24]] (24 bytes of key, 8-byte prefix)
fn stellar_to_contract_field(addr: &str) -> Result<[u8; 32]> {
    let raw = stellar_to_raw(addr)?;
    let mut out = [0u8; 32];
    if addr.starts_with('C') {
        // ScVal XDR slice(4..36) = [0,0,0,1] + hash[0..28]
        out[0..4].copy_from_slice(&[0u8, 0, 0, 1]);
        out[4..].copy_from_slice(&raw[..28]);
    } else {
        // Account G...: ScVal XDR slice(4..36) = [0,0,0,0][0,0,0,0] + key[0..24]
        // first 8 bytes stay 0 (SC_ADDRESS_TYPE_ACCOUNT + KEY_ED25519 discriminants)
        out[8..].copy_from_slice(&raw[..24]);
    }
    Ok(out)
}

fn run_stellar(args: &[&str]) -> Result<String> {
    run_stellar_inner(args, false)
}

fn run_stellar_silent(args: &[&str]) -> Result<String> {
    run_stellar_inner(args, true)
}

fn run_stellar_inner(args: &[&str], silent: bool) -> Result<String> {
    let mut cmd = Command::new("stellar");
    cmd.args(args);
    if silent {
        cmd.stdout(std::process::Stdio::piped())
           .stderr(std::process::Stdio::null());
    }
    let out = cmd.output().context("stellar CLI not found")?;
    if !out.status.success() {
        let stderr = str::from_utf8(&out.stderr).unwrap_or("?");
        bail!("stellar error: {stderr}");
    }
    Ok(str::from_utf8(&out.stdout)?.trim().to_string())
}

// ── tx_bytes construction ──────────────────────────────────────────────────────

/// Compute what the Soroban contract puts in tx_bytes for its own address:
///   env.current_contract_address().to_xdr(env).slice(4..36)
///   = [0,0,0,1] + hash[0..28]  (SC_ADDRESS_TYPE_CONTRACT discriminant + first 28 bytes of hash)
fn contract_id_field(contract_hash: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&[0u8, 0, 0, 1]);
    out[4..].copy_from_slice(&contract_hash[..28]);
    out
}

/// Build the 108-byte tx that the user signs.
/// Matches lib.rs: build_tx_bytes()
///   contract_id(32) || pubkey_hash(32) || nonce(4 LE) || dest(32) || amount(8 BE)
fn build_tx_bytes(
    contract_hash: &[u8; 32],
    pubkey_hash: &[u8; 32],
    nonce: u32,
    dest_field: &[u8; 32],
    amount: i64,
) -> [u8; 108] {
    let mut tx = [0u8; 108];
    tx[0..32].copy_from_slice(&contract_id_field(contract_hash));
    tx[32..64].copy_from_slice(pubkey_hash);
    tx[64..68].copy_from_slice(&nonce.to_le_bytes());
    tx[68..100].copy_from_slice(dest_field);
    tx[100..108].copy_from_slice(&amount.to_be_bytes());
    tx
}

// ── Sindri API ────────────────────────────────────────────────────────────────

const GROTH16_CIRCUIT_ID: &str = "675b1311-8e2b-4b2c-9f16-44a548a3e2b7";
const SINDRI_BASE: &str = "https://sindri.app/api/v1";

fn sindri_prove(api_key: &str, pk: &[u8], tx: &[u8], sig: &[u8]) -> Result<String> {
    fn bincode_vec(data: &[u8]) -> Vec<serde_json::Value> {
        let mut v: Vec<u8> = (data.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(data);
        v.iter().map(|&b| serde_json::json!(b)).collect()
    }

    let stdin = serde_json::json!({
        "buffer": [bincode_vec(pk), bincode_vec(tx), bincode_vec(sig)],
        "ptr": 0,
        "proofs": []
    });

    let resp: serde_json::Value = ureq::post(&format!("{SINDRI_BASE}/circuit/{GROTH16_CIRCUIT_ID}/prove"))
        .header("Authorization", &format!("Bearer {api_key}"))
        .send_json(serde_json::json!({ "proof_input": stdin.to_string() }))?
        .body_mut()
        .read_json()?;

    Ok(resp["proof_id"].as_str().context("no proof_id")?.to_string())
}

fn sindri_poll(api_key: &str, proof_id: &str) -> Result<serde_json::Value> {
    sindri_poll_inner(api_key, proof_id, true)
}

fn sindri_poll_silent(api_key: &str, proof_id: &str) -> Result<serde_json::Value> {
    sindri_poll_inner(api_key, proof_id, false)
}

fn sindri_poll_inner(api_key: &str, proof_id: &str, verbose: bool) -> Result<serde_json::Value> {
    if verbose { println!("Polling proof {}...", &proof_id[..8]); }
    for _ in 0..120 {
        let resp: serde_json::Value = ureq::get(&format!("{SINDRI_BASE}/proof/{proof_id}/detail"))
            .header("Authorization", &format!("Bearer {api_key}"))
            .call()?
            .body_mut()
            .read_json()?;

        match resp["status"].as_str() {
            Some("Ready") => {
                if verbose { println!("  Ready ({})", resp["compute_time"].as_str().unwrap_or("?")); }
                return Ok(resp);
            }
            Some("Failed") | Some("Timed Out") => {
                bail!("Proof failed: {}", resp["error"].as_str().unwrap_or("?"));
            }
            _ => {
                if verbose { print!("."); }
                std::io::Write::flush(&mut std::io::stdout()).ok();
                std::thread::sleep(Duration::from_secs(30));
            }
        }
    }
    bail!("Timed out waiting for proof")
}

// ── Proof parsing ──────────────────────────────────────────────────────────────

fn parse_proof(detail: &serde_json::Value, inputs: &ProofInputs) -> Result<ProofCache> {
    let proof_b64 = detail["proof"]["proof"].as_str().context("no proof.proof field")?;
    let raw = base64::engine::general_purpose::STANDARD.decode(proof_b64)?;
    let parsed = decode_msgpack_proof(&raw)?;

    let enc_proof  = &parsed.enc_proof;
    let vkey_hash  = &parsed.vkey_hash;
    // proof_bytes = vkey_hash[0..4] || enc_proof (260 bytes)
    let mut proof_bytes = Vec::with_capacity(260);
    proof_bytes.extend_from_slice(&vkey_hash[..4]);
    proof_bytes.extend_from_slice(enc_proof);

    // public_values = sha256(pk) || sha256(tx) || wallet_nonce(4 LE)
    // wallet_nonce comes from tx_bytes[64..68] (LE u32), NOT the XMSS leaf index.
    // This must match exactly what the SP1 guest commits.
    let pk = hex::decode(&inputs.public_key)?;
    let tx = hex::decode(&inputs.tx_bytes)?;
    let pubkey_hash: [u8; 32] = Sha256::digest(&pk).into();
    let tx_hash: [u8; 32] = Sha256::digest(&tx).into();
    anyhow::ensure!(tx.len() >= 68, "tx_bytes too short to extract wallet_nonce");
    let wallet_nonce = u32::from_le_bytes(tx[64..68].try_into().unwrap());
    let nonce_bytes = wallet_nonce.to_le_bytes();
    let mut public_values = Vec::with_capacity(68);
    public_values.extend_from_slice(&pubkey_hash);
    public_values.extend_from_slice(&tx_hash);
    public_values.extend_from_slice(&nonce_bytes);

    // program_vkey is already 32-byte BE hex from decimal_to_be32_hex
    let program_vkey = hex::decode(&parsed.pub_input0)?;

    Ok(ProofCache {
        proof_id:     detail["proof_id"].as_str().unwrap_or("?").to_string(),
        proof_bytes:  hex::encode(&proof_bytes),
        public_values: hex::encode(&public_values),
        program_vkey:  hex::encode(&program_vkey),
        pubkey_hash:   hex::encode(pubkey_hash),
        tx_hash:       hex::encode(tx_hash),
        nonce:         wallet_nonce,
        destination:   String::new(), // filled by caller
        amount:        0,             // filled by caller
    })
}

struct MsgpackProof {
    pub_input0:  String,  // program vkey as 32-byte BE hex
    enc_proof:   Vec<u8>, // 256 bytes
    vkey_hash:   Vec<u8>, // 32 bytes
}

fn decode_msgpack_proof(raw: &[u8]) -> Result<MsgpackProof> {
    let mut pos = 0usize;

    // We know the structure:
    // [outer_array] → [inner_map{"Groth16": [pub_inputs, enc_proof_hex, raw_proof_hex, vkey_hash]}]
    // Just decode recursively into serde_json::Value

    fn decode_val(raw: &[u8], pos: &mut usize) -> Result<serde_json::Value> {
        let b = {
            if *pos >= raw.len() { bail!("eof"); }
            let b = raw[*pos]; *pos += 1; b
        };

        match b {
            // fixarray
            0x90..=0x9f => {
                let n = (b & 0x0f) as usize;
                let mut arr = Vec::with_capacity(n);
                for _ in 0..n { arr.push(decode_val(raw, pos)?); }
                Ok(serde_json::Value::Array(arr))
            }
            // fixmap
            0x80..=0x8f => {
                let n = (b & 0x0f) as usize;
                let mut map = serde_json::Map::new();
                for _ in 0..n {
                    let k = decode_val(raw, pos)?.as_str().unwrap_or("?").to_string();
                    let v = decode_val(raw, pos)?;
                    map.insert(k, v);
                }
                Ok(serde_json::Value::Object(map))
            }
            // fixstr
            0xa0..=0xbf => {
                let n = (b & 0x1f) as usize;
                let s = String::from_utf8(raw[*pos..*pos+n].to_vec())?;
                *pos += n;
                Ok(serde_json::Value::String(s))
            }
            // str8
            0xd9 => {
                let n = raw[*pos] as usize; *pos += 1;
                let s = String::from_utf8(raw[*pos..*pos+n].to_vec())?;
                *pos += n;
                Ok(serde_json::Value::String(s))
            }
            // str16
            0xda => {
                let n = u16::from_be_bytes([raw[*pos], raw[*pos+1]]) as usize; *pos += 2;
                let s = String::from_utf8(raw[*pos..*pos+n].to_vec())?;
                *pos += n;
                Ok(serde_json::Value::String(s))
            }
            // bin8
            0xc4 => {
                let n = raw[*pos] as usize; *pos += 1;
                let v: Vec<serde_json::Value> = raw[*pos..*pos+n].iter()
                    .map(|&x| serde_json::json!(x)).collect();
                *pos += n;
                Ok(serde_json::Value::Array(v))
            }
            // bin16
            0xc5 => {
                let n = u16::from_be_bytes([raw[*pos], raw[*pos+1]]) as usize; *pos += 2;
                let v: Vec<serde_json::Value> = raw[*pos..*pos+n].iter()
                    .map(|&x| serde_json::json!(x)).collect();
                *pos += n;
                Ok(serde_json::Value::Array(v))
            }
            // array16
            0xdc => {
                let n = u16::from_be_bytes([raw[*pos], raw[*pos+1]]) as usize; *pos += 2;
                let mut arr = Vec::with_capacity(n);
                for _ in 0..n { arr.push(decode_val(raw, pos)?); }
                Ok(serde_json::Value::Array(arr))
            }
            // positive fixint
            0x00..=0x7f => Ok(serde_json::json!(b)),
            // negative fixint
            0xe0..=0xff => Ok(serde_json::json!(b as i8)),
            // uint8
            0xcc => { let v = raw[*pos]; *pos += 1; Ok(serde_json::json!(v)) }
            // uint16
            0xcd => {
                let v = u16::from_be_bytes([raw[*pos], raw[*pos+1]]); *pos += 2;
                Ok(serde_json::json!(v))
            }
            // uint32
            0xce => {
                let v = u32::from_be_bytes(raw[*pos..*pos+4].try_into().unwrap()); *pos += 4;
                Ok(serde_json::json!(v))
            }
            // uint64
            0xcf => {
                let v = u64::from_be_bytes(raw[*pos..*pos+8].try_into().unwrap()); *pos += 8;
                Ok(serde_json::json!(v))
            }
            _ => bail!("unknown msgpack byte 0x{b:02x} at {}", *pos - 1),
        }
    }

    let val = decode_val(raw, &mut pos)?;

    // Expected: [[{"Groth16": [[pi0, pi1], enc_proof_hex, raw_proof_hex, vkey_hash_bytes]}]]
    let groth16 = val[0]["Groth16"].as_array().context("no Groth16 field")?;
    let pub_inputs = groth16[0].as_array().context("no pub_inputs")?;
    let enc_proof_hex = groth16[1].as_str().context("enc_proof not a string")?;
    let vkey_hash_arr = groth16[3].as_array().context("vkey_hash not array")?;

    // pub_inputs[0] is a decimal string in the msgpack; use as_str() to avoid JSON-quoting.
    let pi0 = pub_inputs[0].as_str().context("pub_inputs[0] not a string")?.to_string();
    let enc_proof = hex::decode(enc_proof_hex)?;
    let vkey_hash: Vec<u8> = vkey_hash_arr.iter()
        .map(|v| v.as_u64().unwrap_or(0) as u8)
        .collect();

    // Convert pi0 (decimal string of u256) to 32-byte BE hex
    let program_vkey_hex = decimal_to_be32_hex(&pi0)?;

    Ok(MsgpackProof {
        pub_input0: program_vkey_hex,
        enc_proof,
        vkey_hash,
    })
}

/// Convert a decimal string representing a 256-bit integer into a 32-byte BE hex string.
fn decimal_to_be32_hex(decimal: &str) -> Result<String> {
    // Simple big-integer decimal-to-bytes conversion
    let mut rem = decimal.to_string();
    let mut bytes = [0u8; 32];
    let mut i = 31i32;
    while !rem.is_empty() && rem != "0" {
        let (q, r) = divmod256(&rem);
        if i < 0 { bail!("number too large for 32 bytes"); }
        bytes[i as usize] = r;
        rem = q;
        i -= 1;
    }
    Ok(hex::encode(bytes))
}

/// Divide a decimal string by 256, return (quotient_str, remainder).
fn divmod256(s: &str) -> (String, u8) {
    let mut result = String::new();
    let mut rem = 0u32;
    for ch in s.chars() {
        let d = rem * 10 + ch.to_digit(10).unwrap_or(0);
        let q = d / 256;
        rem = d % 256;
        if !result.is_empty() || q != 0 {
            result.push(char::from_digit(q, 10).unwrap());
        }
    }
    if result.is_empty() { result.push('0'); }
    (result, rem as u8)
}

// ── Commands ──────────────────────────────────────────────────────────────────

fn cmd_wallet_create(cfg: &Config, key_out: Option<PathBuf>) -> Result<()> {
    let key_path = key_out.as_deref().unwrap_or(&cfg.key_file);

    if key_path.exists() {
        println!("Key file already exists: {}", key_path.display());
        println!("Loading existing keypair...\n");
    } else {
        println!("Generating XMSS-SHA2_10_256 keypair...");
        ensure_xmss_built(cfg)?;
        let status = Command::new(&cfg.xmss_bin)
            .args(["keygen", "--out"])
            .arg(key_path)
            .status()?;
        if !status.success() { bail!("keygen failed"); }
    }

    let key = KeyFile::load(key_path)?;
    let pubkey_hash = key.pubkey_hash()?;

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  XMSS Post-Quantum Wallet");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Algorithm     : XMSS-SHA2_10_256  (RFC 8391, h=10, 1024 one-time keys)");
    println!("  Wallet ID     : {}", hex::encode(pubkey_hash));
    println!("  Keys used     : {}/{}", key.next_index, 1024);
    println!("  Key file      : {}", key_path.display());
    println!();
    println!("  Contract      : {}", cfg.wallet_contract);
    println!();
    println!("  To fund this wallet:");
    println!("    nebula fund --amount <stroops>");
    println!();
    println!("  WARNING: Never share key.json. Back it up securely.");
    println!("  WARNING: XMSS keys are one-time. Each withdrawal burns one key slot.");

    Ok(())
}

fn cmd_wallet_info(cfg: &Config, pubkey_hash_override: Option<String>) -> Result<()> {
    let pubkey_hash_hex = match pubkey_hash_override {
        Some(h) => h,
        None => {
            let key = KeyFile::load(&cfg.key_file)?;
            hex::encode(key.pubkey_hash()?)
        }
    };

    println!("Querying wallet {} ...", &pubkey_hash_hex[..16]);

    let balance = run_stellar(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", &cfg.stellar_account,
        "--network", "testnet",
        "--", "balance",
        "--pubkey_hash", &pubkey_hash_hex,
    ])?;

    let nonce = run_stellar(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", &cfg.stellar_account,
        "--network", "testnet",
        "--", "nonce",
        "--pubkey_hash", &pubkey_hash_hex,
    ])?;

    let balance_n: i64 = balance.trim_matches('"').parse().unwrap_or(0);
    let nonce_n: u32 = nonce.trim_matches('"').parse().unwrap_or(0);

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Wallet: {}", pubkey_hash_hex);
    println!("  Balance : {} stroops  ({:.7} XLM)", balance_n, balance_n as f64 / 10_000_000.0);
    println!("  Nonce   : {}  (XMSS leaves used: at least {} of 1024)", nonce_n, nonce_n);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(())
}

fn cmd_fund(cfg: &Config, amount: i64, to_override: Option<String>, from_override: Option<String>) -> Result<()> {
    let pubkey_hash = match to_override {
        Some(ref h) => h.clone(),
        None => {
            let key = KeyFile::load(&cfg.key_file)?;
            hex::encode(key.pubkey_hash()?)
        }
    };
    let from = from_override.as_deref().unwrap_or(&cfg.stellar_account);

    println!("Depositing {} stroops ({:.7} XLM) into wallet {}...",
        amount, amount as f64 / 10_000_000.0, &pubkey_hash[..16]);

    // Get the depositor's Stellar address
    let depositor_addr = run_stellar(&["keys", "address", from])?;

    let out = run_stellar(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", from,
        "--network", "testnet",
        "--", "deposit",
        "--from", &depositor_addr,
        "--pubkey_hash", &pubkey_hash,
        "--amount", &amount.to_string(),
    ])?;

    println!("Deposit successful!");
    println!("  tx: {out}");
    println!();

    cmd_wallet_info(cfg, Some(pubkey_hash))
}

fn cmd_intent(cfg: &Config, destination: &str, amount: i64) -> Result<()> {
    let key = KeyFile::load(&cfg.key_file)?;
    let pubkey_hash = key.pubkey_hash()?;
    let pubkey_hash_hex = hex::encode(pubkey_hash);

    // Query current nonce
    let nonce_str = run_stellar(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", &cfg.stellar_account,
        "--network", "testnet",
        "--", "nonce",
        "--pubkey_hash", &pubkey_hash_hex,
    ])?;
    let nonce: u32 = nonce_str.trim_matches('"').parse().unwrap_or(0);

    let dest_field = stellar_to_contract_field(destination)?;
    let tx = build_tx_bytes(&cfg.contract_hash, &pubkey_hash, nonce, &dest_field, amount);

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Withdrawal Intent");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Wallet       : {pubkey_hash_hex}");
    println!("  Destination  : {destination}");
    println!("  Amount       : {amount} stroops  ({:.7} XLM)", amount as f64 / 10_000_000.0);
    println!("  Nonce        : {nonce}");
    println!("  tx_bytes     : {}", hex::encode(tx));
    println!("  sha256(tx)   : {}", hex::encode(Sha256::digest(tx)));
    println!();
    println!("  To proceed:");
    println!("    nebula withdraw --destination {destination} --amount {amount}");

    Ok(())
}

fn cmd_prove_only(cfg: &Config, proof_id_override: Option<String>) -> Result<()> {
    if !cfg.proof_inputs.exists() {
        bail!("proof_inputs.json not found — run `nebula withdraw` first");
    }
    let inputs: ProofInputs = serde_json::from_str(&std::fs::read_to_string(&cfg.proof_inputs)?)?;

    let proof_id = match proof_id_override {
        Some(id) => id,
        None => {
            let pk  = hex::decode(&inputs.public_key)?;
            let tx  = hex::decode(&inputs.tx_bytes)?;
            let sig = hex::decode(&inputs.signature)?;
            println!("Submitting to Sindri...");
            let id = sindri_prove(&cfg.sindri_api_key, &pk, &tx, &sig)?;
            println!("  Proof job: {id}");
            id
        }
    };

    let detail = sindri_poll(&cfg.sindri_api_key, &proof_id)?;
    let parsed = parse_proof(&detail, &inputs)?;

    std::fs::write(&cfg.proof_cache, serde_json::to_string_pretty(&parsed)?)?;
    println!("Proof cached → {}", cfg.proof_cache.display());
    println!("  proof_bytes   : {} bytes", parsed.proof_bytes.len() / 2);
    println!("  public_values : {} bytes", parsed.public_values.len() / 2);
    println!("  nonce         : {}", parsed.nonce);

    Ok(())
}

fn cmd_submit(cfg: &Config, destination: &str, amount: i64) -> Result<()> {
    if !cfg.proof_cache.exists() {
        bail!("groth16_proof.json not found — run `nebula prove` first");
    }
    let cache: ProofCache = serde_json::from_str(&std::fs::read_to_string(&cfg.proof_cache)?)?;
    do_submit(cfg, &cache, destination, amount)
}

fn do_submit(cfg: &Config, cache: &ProofCache, destination: &str, amount: i64) -> Result<()> {
    do_submit_inner(cfg, cache, destination, amount, false).map(|_| ())
}

fn do_submit_silent(cfg: &Config, cache: &ProofCache, destination: &str, amount: i64) -> Result<String> {
    do_submit_inner(cfg, cache, destination, amount, true)
}

fn do_submit_inner(cfg: &Config, cache: &ProofCache, destination: &str, amount: i64, silent: bool) -> Result<String> {
    if !silent {
        println!("Submitting withdrawal to chain...");
        println!("  destination : {destination}");
        println!("  amount      : {amount} stroops ({:.7} XLM)", amount as f64 / 10_000_000.0);
        println!("  proof nonce : {}", cache.nonce);
    }

    let out = run_stellar_silent(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", &cfg.stellar_account,
        "--network", "testnet",
        "--", "withdraw",
        "--proof_bytes",   &cache.proof_bytes,
        "--public_values", &cache.public_values,
        "--destination",   destination,
        "--amount",        &amount.to_string(),
    ])?;

    if !silent {
        println!();
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  Withdrawal complete!");
        println!("  tx: {out}");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    Ok(out)
}

fn cmd_withdraw(
    cfg: &Config,
    destination: &str,
    amount: i64,
    skip_sign: bool,
    skip_prove: bool,
    proof_id_override: Option<String>,
) -> Result<()> {
    // ── Step 1: Sign ──────────────────────────────────────────────────────────
    if !skip_sign && !skip_prove && proof_id_override.is_none() {
        let key = KeyFile::load(&cfg.key_file)?;
        let pubkey_hash = key.pubkey_hash()?;
        let pubkey_hash_hex = hex::encode(pubkey_hash);

        // Query nonce from chain
        let nonce_str = run_stellar(&[
            "contract", "invoke",
            "--id", &cfg.wallet_contract,
            "--source-account", &cfg.stellar_account,
            "--network", "testnet",
            "--", "nonce",
            "--pubkey_hash", &pubkey_hash_hex,
        ])?;
        let nonce: u32 = nonce_str.trim_matches('"').parse().unwrap_or(0);
        println!("Wallet nonce: {nonce}");

        let dest_field = stellar_to_contract_field(destination)?;
        let tx = build_tx_bytes(&cfg.contract_hash, &pubkey_hash, nonce, &dest_field, amount);
        let tx_hex = hex::encode(tx);
        println!("tx_bytes ({}B): {}...", tx.len(), &tx_hex[..32]);

        ensure_xmss_built(cfg)?;
        println!("Signing with XMSS (leaf {})...", key.next_index);
        let status = Command::new(&cfg.xmss_bin)
            .args(["sign", "--key"])
            .arg(&cfg.key_file)
            .args(["--tx", &tx_hex, "--out"])
            .arg(&cfg.proof_inputs)
            .status()?;
        if !status.success() { bail!("XMSS signing failed"); }
        println!("Signed → {}", cfg.proof_inputs.display());
    } else if !cfg.proof_inputs.exists() {
        bail!("proof_inputs.json not found — run without --skip-sign first");
    }

    // ── Step 2: Prove ─────────────────────────────────────────────────────────
    let inputs: ProofInputs = serde_json::from_str(&std::fs::read_to_string(&cfg.proof_inputs)?)?;

    let proof_cache = if skip_prove {
        if !cfg.proof_cache.exists() {
            bail!("groth16_proof.json not found — run without --skip-prove first");
        }
        serde_json::from_str(&std::fs::read_to_string(&cfg.proof_cache)?)?
    } else {
        let proof_id = match proof_id_override {
            Some(id) => id,
            None => {
                let pk  = hex::decode(&inputs.public_key)?;
                let tx  = hex::decode(&inputs.tx_bytes)?;
                let sig = hex::decode(&inputs.signature)?;
                println!("Submitting to Sindri...");
                let id = sindri_prove(&cfg.sindri_api_key, &pk, &tx, &sig)?;
                println!("  Proof job: {id}");
                id
            }
        };

        let detail = sindri_poll(&cfg.sindri_api_key, &proof_id)?;
        let mut cache = parse_proof(&detail, &inputs)?;
        cache.destination = destination.to_string();
        cache.amount = amount;
        std::fs::write(&cfg.proof_cache, serde_json::to_string_pretty(&cache)?)?;
        println!("Proof cached → {}", cfg.proof_cache.display());
        cache
    };

    // ── Step 3: Submit ────────────────────────────────────────────────────────
    do_submit(cfg, &proof_cache, destination, amount)
}

// ── Silent withdraw (for TUI — no stdout pollution) ──────────────────────────

fn cmd_withdraw_silent(cfg: &Config, destination: &str, amount: i64) -> Result<String> {
    let key = KeyFile::load(&cfg.key_file)?;
    let pubkey_hash = key.pubkey_hash()?;
    let pubkey_hash_hex = hex::encode(pubkey_hash);

    let nonce_str = run_stellar_silent(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", &cfg.stellar_account,
        "--network", "testnet",
        "--", "nonce",
        "--pubkey_hash", &pubkey_hash_hex,
    ])?;
    let nonce: u32 = nonce_str.trim_matches('"').parse().unwrap_or(0);

    let dest_field = stellar_to_contract_field(destination)?;
    let tx = build_tx_bytes(&cfg.contract_hash, &pubkey_hash, nonce, &dest_field, amount);
    let tx_hex = hex::encode(tx);

    ensure_xmss_built(cfg)?;
    let status = Command::new(&cfg.xmss_bin)
        .args(["sign", "--key"])
        .arg(&cfg.key_file)
        .args(["--tx", &tx_hex, "--out"])
        .arg(&cfg.proof_inputs)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() { bail!("XMSS signing failed"); }

    let inputs: ProofInputs = serde_json::from_str(&std::fs::read_to_string(&cfg.proof_inputs)?)?;
    let pk  = hex::decode(&inputs.public_key)?;
    let tx_b = hex::decode(&inputs.tx_bytes)?;
    let sig = hex::decode(&inputs.signature)?;
    let proof_id = sindri_prove(&cfg.sindri_api_key, &pk, &tx_b, &sig)?;

    let detail = sindri_poll_silent(&cfg.sindri_api_key, &proof_id)?;
    let mut cache = parse_proof(&detail, &inputs)?;
    cache.destination = destination.to_string();
    cache.amount = amount;
    std::fs::write(&cfg.proof_cache, serde_json::to_string_pretty(&cache)?)?;

    do_submit_silent(cfg, &cache, destination, amount)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ensure_xmss_built(cfg: &Config) -> Result<()> {
    if cfg.xmss_bin.exists() { return Ok(()); }
    println!("Building XMSS binary...");
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(cfg.project_root.join("xmss"))
        .status()?;
    if !status.success() { bail!("cargo build failed for xmss"); }
    Ok(())
}

// ── TUI command ───────────────────────────────────────────────────────────────

fn cmd_ui(cfg: &Config) -> Result<()> {
    // Load key
    let key = KeyFile::load(&cfg.key_file)?;
    let pubkey_hash = key.pubkey_hash()?;
    let pubkey_hash_hex = hex::encode(pubkey_hash);

    // Fetch balance + nonce from chain
    let balance_raw = run_stellar(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", &cfg.stellar_account,
        "--network", "testnet",
        "--", "balance",
        "--pubkey_hash", &pubkey_hash_hex,
    ]).unwrap_or_else(|_| "0".into());
    let balance: i64 = balance_raw.trim_matches('"').parse().unwrap_or(0);

    let nonce_raw = run_stellar(&[
        "contract", "invoke",
        "--id", &cfg.wallet_contract,
        "--source-account", &cfg.stellar_account,
        "--network", "testnet",
        "--", "nonce",
        "--pubkey_hash", &pubkey_hash_hex,
    ]).unwrap_or_else(|_| "0".into());
    let nonce: u32 = nonce_raw.trim_matches('"').parse().unwrap_or(0);

    let wallet_info = tui::WalletInfo {
        pubkey_hash: pubkey_hash_hex,
        balance_stroops: balance,
        nonce,
        leaves_used: key.next_index,
        leaves_total: 1024,
    };

    // Build history from proof cache if available
    let mut history = Vec::new();
    if cfg.proof_cache.exists() {
        if let Ok(text) = std::fs::read_to_string(&cfg.proof_cache) {
            if let Ok(cache) = serde_json::from_str::<ProofCache>(&text) {
                if !cache.destination.is_empty() {
                    history.push(tui::TxHistory {
                        amount_stroops: cache.amount,
                        destination: cache.destination,
                        nonce: cache.nonce,
                    });
                }
            }
        }
    }

    let cfg_ref = cfg;
    tui::run_tui(wallet_info, history, move |dest, amount| {
        cmd_withdraw_silent(cfg_ref, dest, amount)
    })
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let result = run(cli);
    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let cfg = Config::load()?;
    match cli.command {
        Cmd::Wallet { action } => match action {
            WalletAction::Create { key_out } => cmd_wallet_create(&cfg, key_out),
            WalletAction::Info { pubkey_hash } => cmd_wallet_info(&cfg, pubkey_hash),
        },
        Cmd::Fund { amount, to, from } => cmd_fund(&cfg, amount, to, from),
        Cmd::Intent { destination, amount } => cmd_intent(&cfg, &destination, amount),
        Cmd::Withdraw { destination, amount, skip_sign, skip_prove, proof_id } =>
            cmd_withdraw(&cfg, &destination, amount, skip_sign, skip_prove, proof_id),
        Cmd::Prove { proof_id } => cmd_prove_only(&cfg, proof_id),
        Cmd::Submit { destination, amount } => cmd_submit(&cfg, &destination, amount),
        Cmd::Ui => cmd_ui(&cfg),
    }
}
