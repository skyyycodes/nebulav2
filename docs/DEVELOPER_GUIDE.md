<div align="center">

# 🔧 Nebula — Developer Guide

### Build from source, deploy your own contract, extend the project.

</div>

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Repository Structure](#2-repository-structure)
3. [Build from Source](#3-build-from-source)
4. [Running Tests](#4-running-tests)
5. [Deploy Your Own Soroban Contract](#5-deploy-your-own-soroban-contract)
6. [Develop the SP1 Circuit](#6-develop-the-sp1-circuit)
7. [Develop the Browser Extension](#7-develop-the-browser-extension)
8. [Run the Relay Server](#8-run-the-relay-server)
9. [Environment Configuration](#9-environment-configuration)
10. [Contributing](#10-contributing)

---

## 1. Prerequisites

### Required Tools

| Tool | Version | Installation |
|------|---------|-------------|
| **Rust** | ≥ 1.79 | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| **Stellar CLI** | ≥ 0.5.6 | `cargo install --locked stellar-cli --features opt` |
| **Node.js** | ≥ 20 | [nodejs.org](https://nodejs.org) |
| **Docker** | ≥ 24 | [docker.com](https://docker.com) (for relay server) |

### Optional (for SP1 circuit development)

| Tool | Version | Installation |
|------|---------|-------------|
| **SP1 toolchain** | 4.x | `curl -L https://sp1up.succinct.xyz \| bash && sp1up` |
| **wasm-pack** | latest | `cargo install wasm-pack` |

### Required Accounts

| Service | Purpose | Sign up |
|---------|---------|---------|
| **Sindri** | ZK proof generation | [sindri.app](https://sindri.app) |
| **Stellar Testnet account** | Funding transactions | Any Stellar testnet faucet |

---

## 2. Repository Structure

```
nebulav2/
├── cli/                    # Rust CLI binary (nebula command)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # 1,113 lines — command orchestration
│       └── tui.rs          # 529 lines  — Ratatui TUI dashboard
│
├── sp1/                    # SP1 zkVM circuit
│   ├── program/            # Guest program (compiled to ELF for Sindri)
│   │   ├── Cargo.toml
│   │   └── src/main.rs     # 245 lines — XMSS verifier (no_std)
│   └── script/             # Local proving helper scripts
│       ├── Cargo.toml
│       └── src/
│           ├── gen_stdin.rs
│           └── submit.rs
│
├── soroban/                # Stellar smart contract
│   ├── Cargo.toml
│   └── src/lib.rs          # 473 lines — Groth16 verifier + XLM transfer
│
├── xmss/                   # XMSS CLI tool
│   ├── Cargo.toml
│   └── src/main.rs
│
├── xmss-wasm/              # XMSS compiled to WebAssembly
│   ├── Cargo.toml
│   └── src/lib.rs
│
├── extension/              # Chrome MV3 browser extension
│   ├── manifest.json
│   ├── package.json
│   ├── vite.config.ts
│   └── src/
│       ├── background.ts   # Service worker
│       ├── popup.tsx       # React UI
│       └── crypto.ts       # Key helpers
│
├── relayer/                # Node.js relay server
│   ├── server.js
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── package.json
│
├── prover/                 # Legacy Risc0 prover (superseded by sp1/)
├── noir/                   # Legacy Noir circuit (superseded by sp1/)
│
├── docs/                   # Documentation
│   ├── NON_TECHNICAL_GUIDE.md
│   ├── TECHNICAL_REFERENCE.md
│   └── DEVELOPER_GUIDE.md  ← you are here
│
├── ARCHITECTURE.md
├── DEVLOG.md
├── README.md
└── install.sh
```

---

## 3. Build from Source

### 3.1 Clone the Repository

```bash
git clone https://github.com/Eshan276/nebulav2.git
cd nebulav2
```

### 3.2 Build the XMSS Tool

```bash
cd xmss
cargo build --release
# Binary: target/release/xmss
```

Test keygen and signing:

```bash
./target/release/xmss keygen --out /tmp/test_key.json
./target/release/xmss sign \
  --key /tmp/test_key.json \
  --tx 000102030405060708090a0b0c0d0e0f \
  --nonce 0 \
  --out /tmp/test_proof_inputs.json
./target/release/xmss verify \
  --key /tmp/test_key.json \
  --inputs /tmp/test_proof_inputs.json
```

### 3.3 Build the Nebula CLI

```bash
cd cli
cargo build --release
# Binary: target/release/nebula
```

To install to `~/.local/bin`:

```bash
cp target/release/nebula ~/.local/bin/
```

### 3.4 Build the Soroban Contract

```bash
cd soroban
stellar contract build
# Output: target/wasm32-unknown-unknown/release/sphincs_verifier.wasm
```

Or build manually:

```bash
cargo build --target wasm32-unknown-unknown --release
```

### 3.5 Build the SP1 Circuit ELF

Requires the SP1 toolchain:

```bash
# Install SP1 toolchain
curl -L https://sp1up.succinct.xyz | bash
sp1up

# Build the ELF
cd sp1/program
cargo prove build
# Output: elf/xmss-sp1-program
```

### 3.6 Build the Browser Extension

```bash
cd extension
npm install
npm run build
# Output: dist/
```

The `dist/` folder can be loaded as an unpacked extension in Chrome (`chrome://extensions` → "Load unpacked").

To watch for changes during development:

```bash
npm run dev
```

### 3.7 Build the XMSS WebAssembly Module

```bash
cd xmss-wasm
wasm-pack build --target bundler
# Output: pkg/
```

---

## 4. Running Tests

### Soroban Contract Tests

```bash
cd soroban
cargo test
```

The contract includes integration tests that use `soroban-sdk`'s test environment to simulate deposits and withdrawals without requiring a live network.

### XMSS Tool Tests

```bash
cd xmss
cargo test
```

### SP1 Circuit Tests (Local Proving)

> ⚠️ Local SP1 proving does **not** produce a Groth16 proof. It runs the circuit in "dev mode" to verify correctness without full proving overhead.

```bash
cd sp1/script
RUST_LOG=info cargo run --release -- --dev-mode \
  --pk-file /tmp/test_key.json \
  --tx-bytes 00112233...
```

### CLI Unit Tests

```bash
cd cli
cargo test
```

---

## 5. Deploy Your Own Soroban Contract

### 5.1 Set Up a Stellar Account

```bash
# Create and fund a testnet account
stellar keys generate quantum-deployer --network testnet
stellar keys address quantum-deployer

# Fund via testnet faucet
curl "https://friendbot.stellar.org?addr=$(stellar keys address quantum-deployer)"
```

### 5.2 Build the Contract

```bash
cd soroban
stellar contract build
```

### 5.3 Deploy to Testnet

```bash
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/sphincs_verifier.wasm \
  --source quantum-deployer \
  --network testnet
```

Note the **contract ID** in the output (`C...`).

### 5.4 Find the XLM SAC Address

```bash
stellar contract id asset \
  --asset native \
  --network testnet
```

### 5.5 Obtain Your SP1 Program VKey

After uploading your SP1 circuit to Sindri, extract the `program_vkey` (the hash of your ELF). This is the `pub_input_0` value from any proof generated by the circuit.

From a `groth16_proof.json`:

```bash
# The first 32 bytes of public_values are pubkey_hash
# The program_vkey comes from Sindri's proof metadata
jq '.program_vkey' groth16_proof.json
```

### 5.6 Initialize the Contract

```bash
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source quantum-deployer \
  --network testnet \
  -- init \
  --vkey <PROGRAM_VKEY_HEX> \
  --xlm_sac <XLM_SAC_ADDRESS>
```

### 5.7 Update the CLI Configuration

The CLI has environment variables baked in at compile time. Update `cli/src/main.rs`:

```rust
const WALLET_CONTRACT_ID: &str = "C...your_contract...";
const WALLET_CONTRACT_HASH: &str = "hex...your_contract_inner_hash...";
const SINDRI_API_KEY: &str = "your_sindri_api_key";
```

Then rebuild:

```bash
cd cli && cargo build --release
```

---

## 6. Develop the SP1 Circuit

### 6.1 Circuit Architecture

The SP1 circuit is in `sp1/program/src/main.rs`. It is a standard Rust `no_std` program that runs inside SP1's RISC-V zkVM.

Key constraints:
- No heap allocations using external allocators (use stack or `sp1_zkvm` primitives)
- No `std::time`, `std::fs`, or OS-dependent code
- Only `sha2 = "0.10"` and `sp1-zkvm = "4.1.3"` as dependencies

### 6.2 Local Development Loop

```bash
# Run in dev mode (no proof, just execution)
cd sp1/script
RUST_LOG=info cargo run --release -- \
  --pk-file /path/to/key.json \
  --tx-bytes <108-byte hex>
```

This confirms the circuit executes correctly before submitting to Sindri.

### 6.3 Upload to Sindri

After modifying the circuit:

1. Rebuild the ELF: `cd sp1/program && cargo prove build`
2. Upload to Sindri via their dashboard or CLI
3. Note the new **circuit ID**
4. Update the circuit ID in `cli/src/main.rs`
5. Redeploy the Soroban contract with the new `program_vkey`

> ⚠️ The `program_vkey` stored in the Soroban contract must match the circuit. Changing the circuit requires redeploying the contract.

---

## 7. Develop the Browser Extension

### 7.1 Development Setup

```bash
cd extension
npm install
npm run dev   # Watch mode — rebuilds on file changes
```

### 7.2 Load in Chrome

1. Open `chrome://extensions`
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select the `extension/dist/` folder

### 7.3 Architecture

| File | Role |
|------|------|
| `background.ts` | Service worker — IndexedDB storage, Sindri API calls, proof orchestration |
| `popup.tsx` | React UI — shows balance/nonce/keys, handles send form |
| `crypto.ts` | XMSS key serialization helpers |
| `xmss-wasm` | Loaded at runtime via `import()` for keygen and signing |

### 7.4 Key Storage

Keys are persisted in **IndexedDB** (`nebula-db`, store `keys`). The full `key.json` object (including `next_index`) is stored as a JSON blob under the key `"xmss"`.

### 7.5 Message Protocol

Popup → Background communication uses Chrome's `chrome.runtime.sendMessage`:

```typescript
// From popup.tsx
chrome.runtime.sendMessage({ type: "GET_BALANCE" }, (response) => {
  console.log(response.balance);
});

// In background.ts
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_BALANCE") { /* ... */ }
});
```

---

## 8. Run the Relay Server

### 8.1 Purpose

The relay server bypasses Stellar testnet's limitation where `simulateTransaction` doesn't enable BN254 pairing host functions.

### 8.2 Configuration

Set environment variables:

```bash
export RELAYER_SECRET="S...your_stellar_secret_key..."
export CONTRACT_ID="CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B"
export NETWORK="testnet"
export PORT=3000
```

### 8.3 Run with Docker

```bash
cd relayer

# Build the image
docker build -t nebula-relay .

# Run
docker run -d \
  -p 3000:3000 \
  -e RELAYER_SECRET="$RELAYER_SECRET" \
  -e CONTRACT_ID="$CONTRACT_ID" \
  -e NETWORK="testnet" \
  nebula-relay
```

### 8.4 Run without Docker

```bash
cd relayer
node server.js
```

### 8.5 Test the Relay

```bash
curl -X POST http://localhost:3000/relay \
  -H "Content-Type: application/json" \
  -d '{
    "proof_bytes": "00000001...",
    "public_values": "...",
    "destination": "GDEST...ADDR",
    "amount_stroops": 100000000
  }'
```

Expected response:
```json
{ "txHash": "abc123..." }
```

---

## 9. Environment Configuration

### CLI Build-Time Constants (cli/src/main.rs)

```rust
const WALLET_CONTRACT_ID: &str   = "CCQ4R5...";
const WALLET_CONTRACT_HASH: &str = "<32-byte hex>";
const SINDRI_API_KEY: &str       = "<sindri_key>";
const STELLAR_ACCOUNT: &str      = "quantum-deployer";
const CIRCUIT_ID: &str           = "675b1311-...";
```

### Relay Server Environment Variables

| Variable | Description | Required |
|----------|-------------|---------|
| `RELAYER_SECRET` | Stellar secret key for signing relay transactions | ✅ Yes |
| `CONTRACT_ID` | Soroban contract address | ✅ Yes |
| `NETWORK` | `testnet` or `mainnet` | ✅ Yes |
| `PORT` | HTTP server port (default: 3000) | No |

### Stellar CLI Account Setup

```bash
# Create account
stellar keys generate quantum-deployer --network testnet

# Add to .stellar/config (or pass --source to each command)
stellar keys ls
```

---

## 10. Contributing

### Code Style

- **Rust**: `cargo fmt` and `cargo clippy` before committing
- **TypeScript**: ESLint + Prettier (configured in `extension/`)
- **Commit messages**: Conventional Commits format (`feat:`, `fix:`, `docs:`, etc.)

### Adding a New Command to the CLI

1. Add the command variant to the `Commands` enum in `cli/src/main.rs`
2. Handle it in the `match commands { ... }` block
3. Add integration tests in `cli/src/main.rs` (test module at bottom)

### Modifying the Smart Contract

After changing `soroban/src/lib.rs`:

1. Run `cargo test` in the `soroban/` directory
2. Rebuild: `stellar contract build`
3. Redeploy to testnet (see §5)
4. If the `withdraw` function signature changed, update the CLI accordingly
5. If a new `program_vkey` is produced, update `DataKey::ProgramVKey` via `init()`

### Modifying the SP1 Circuit

After changing `sp1/program/src/main.rs`:

1. Verify locally: `RUST_LOG=info cargo run --release -- --dev-mode`
2. Rebuild ELF: `cargo prove build`
3. Upload new circuit to Sindri → get new circuit ID
4. Update circuit ID in CLI
5. Get new `program_vkey` from a test proof
6. Redeploy the Soroban contract with new `vkey`

> ⚠️ Any circuit change requires a full contract redeployment. Plan accordingly.

---

<div align="center">

**See also:** [Architecture Guide](../ARCHITECTURE.md) · [Technical Reference](./TECHNICAL_REFERENCE.md) · [Non-Technical Guide](./NON_TECHNICAL_GUIDE.md) · [Dev Log](../DEVLOG.md)

</div>
