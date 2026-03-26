<div align="center">

# 🌌 Nebula

### The Post-Quantum Wallet for Stellar

**Send XLM using XMSS signatures verified on-chain via a ZK proof.**  
*No classical cryptography in the signing path. Quantum-resistant by design.*

[![Network](https://img.shields.io/badge/Network-Stellar%20Testnet-7B2FBE?style=for-the-badge&logo=stellar&logoColor=white)](https://stellar.org)
[![Language](https://img.shields.io/badge/Built%20with-Rust-F46623?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![ZK Proof](https://img.shields.io/badge/ZK-SP1%20%2B%20Groth16-00C7B7?style=for-the-badge)](https://succinct.xyz)
[![Signature](https://img.shields.io/badge/Sig-XMSS%20NIST%20SP%20800--208-blue?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-208/final)
[![Status](https://img.shields.io/badge/Status-Live%20on%20Testnet-brightgreen?style=for-the-badge)]()

<img width="1406" height="1021" alt="nebula-architecture" src="https://github.com/user-attachments/assets/9cf3df54-0fb3-424e-85cf-432ab8e2c1b1" />

</div>

---

## ✨ What is Nebula?

Nebula is the world's first **post-quantum smart wallet on Stellar**. It replaces classical ECDSA signing (vulnerable to quantum computers) with **XMSS** — a hash-based, NIST-standardized signature scheme — and uses **zero-knowledge proofs** to verify signatures on-chain without ever exposing your key.

```
Your XMSS key  →  SP1 zkVM circuit  →  Groth16 proof (Sindri)  →  Soroban contract  →  XLM transfer
```

> 🔗 **Live contract on Stellar testnet:**  
> `CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B`

---

## 🏗️ Architecture at a Glance

```mermaid
flowchart TD
    User(["👤 User"])

    subgraph Local["🖥️  Local Machine"]
        CLI["⚙️ Nebula CLI\ncli/src/main.rs"]
        XMSS["🔑 XMSS Tool\nkeygen · sign · verify"]
        KEY[("🗄️ key.json\nXMSS keypair")]
    end

    subgraph Cloud["☁️  Cloud / Network"]
        SINDRI["🧮 Sindri\nGroth16 proving\n(BN254 curve)"]
        SP1["📐 SP1 zkVM\nRISC-V circuit\nXMSS verifier"]
    end

    subgraph Chain["🔗  Stellar Testnet"]
        SOROBAN["📜 Soroban Contract\nGroth16 verify\nXLM transfer"]
        LEDGER[("📒 Stellar Ledger\nbalance · nonce")]
    end

    User -->|"nebula withdraw"| CLI
    CLI -->|"read key"| KEY
    KEY --> XMSS
    XMSS -->|"sig + tx_bytes"| CLI
    CLI -->|"SP1Stdin JSON"| SINDRI
    SINDRI -->|"runs circuit"| SP1
    SP1 -->|"Groth16 proof\n260 bytes"| SINDRI
    SINDRI -->|"proof_bytes +\npublic_values"| CLI
    CLI -->|"stellar invoke withdraw"| SOROBAN
    SOROBAN -->|"BN254 pairing\nverification"| SOROBAN
    SOROBAN -->|"transfer XLM"| LEDGER

    style Local fill:#1a1a2e,stroke:#7B2FBE,color:#fff
    style Cloud fill:#16213e,stroke:#00C7B7,color:#fff
    style Chain fill:#0f3460,stroke:#F46623,color:#fff
```

📖 **Want the full deep-dive?** See [`ARCHITECTURE.md`](./ARCHITECTURE.md)

---

## 📚 Documentation

| Audience | Document | Description |
|---|---|---|
| 🌱 **New Users** | [`docs/NON_TECHNICAL_GUIDE.md`](./docs/NON_TECHNICAL_GUIDE.md) | Plain-English guide — no crypto background needed |
| ⚙️ **Developers** | [`docs/TECHNICAL_REFERENCE.md`](./docs/TECHNICAL_REFERENCE.md) | Complete technical specification & data formats |
| 🔧 **Contributors** | [`docs/DEVELOPER_GUIDE.md`](./docs/DEVELOPER_GUIDE.md) | Build from source, testing, deployment |
| 🏛️ **Architects** | [`ARCHITECTURE.md`](./ARCHITECTURE.md) | System design, component diagrams, data flows |
| 📓 **History** | [`DEVLOG.md`](./DEVLOG.md) | Full engineering journal — every bug and decision |

---

## 🚀 Quick Start

### 1 · Install

**Linux / macOS — one line:**

```bash
curl -fsSL https://raw.githubusercontent.com/Eshan276/nebulav2/main/install.sh | bash
```

This downloads a pre-built binary for your platform (Linux x86\_64 · macOS ARM64 · macOS x86\_64) to `~/.local/bin`.

<details>
<summary>PATH setup (if needed)</summary>

Add to `~/.bashrc` or `~/.zshrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload:

```bash
source ~/.bashrc   # or ~/.zshrc
```

</details>

Verify:

```bash
nebula --help
```

> No `.env` file needed — all configuration is baked into the binary.

---

### 2 · Create a Wallet

```bash
nebula wallet create
```

Generates your XMSS keypair and saves it to `key.json`.

> ⚠️ **Back up `key.json` — losing it means losing access to your wallet.**

---

### 3 · Check Balance

```bash
nebula wallet info
```

---

### 4 · Fund Your Wallet

```bash
nebula fund --amount 100
```

Deposits 100 XLM from your standard Stellar account into your XMSS wallet contract.

---

### 5 · Send XLM

```bash
nebula withdraw --to GDEST...ADDR --amount 10
```

Signs locally with XMSS → generates ZK proof (~30–60 s) → submits on-chain. Done.

---

### 6 · Interactive Dashboard

```bash
nebula ui
```

Full terminal UI showing balance, nonce, XMSS keys remaining, and a send wizard.

---

## 🔬 How It Works

```mermaid
sequenceDiagram
    actor User
    participant CLI as Nebula CLI
    participant XMSS as XMSS Tool
    participant Sindri as Sindri Cloud
    participant Chain as Soroban Contract

    User->>CLI: nebula withdraw --to ADDR --amount 10
    CLI->>Chain: query nonce(pubkey_hash)
    Chain-->>CLI: nonce = N
    CLI->>XMSS: sign(tx_bytes, key.json)
    XMSS-->>CLI: signature (2500 bytes)
    CLI->>Sindri: POST /prove { SP1Stdin }
    Note over Sindri: SP1 zkVM runs<br/>XMSS verifier circuit
    Sindri-->>CLI: Groth16 proof (260 bytes)
    CLI->>Chain: invoke withdraw(proof, public_values, dest, amount)
    Note over Chain: BN254 pairing check<br/>nonce & tx_hash check
    Chain-->>User: ✅ XLM transferred
```

1. **XMSS signing** — Your private key signs the transaction locally. The key never leaves your machine.
2. **ZK proof generation** — SP1 runs an XMSS verifier circuit inside a RISC-V zkVM and compiles the result to a Groth16 proof via Sindri's cloud.
3. **On-chain verification** — The Soroban contract verifies the Groth16 proof using native BN254 pairing host functions, checks the nonce, and atomically transfers XLM.

> The contract never sees your private key or signature — only a mathematical proof that they existed.

---

## 🛡️ Why Post-Quantum?

| Scheme | Vulnerable to Quantum? | Used by |
|---|---|---|
| **ECDSA / ed25519** | ✅ Yes (Shor's algorithm) | Bitcoin, Ethereum, Stellar (native) |
| **XMSS** | ❌ No (hash-based) | **Nebula** |

XMSS (NIST SP 800-208 / RFC 8391) uses only hash functions internally. Quantum computers cannot break hash functions efficiently. Your funds remain secure even against a quantum adversary.

### XMSS Key Limits

`XMSS-SHA2_10_256` provides **1,024 one-time signing keys** per wallet. Each withdrawal consumes one leaf. The `nebula ui` dashboard shows how many remain. When exhausted, generate a new wallet and migrate funds with a standard withdrawal.

---

## 🔒 Security Notes

| Concern | Detail |
|---|---|
| **Key storage** | `key.json` is your XMSS private key. Never commit it to version control or upload it unencrypted. |
| **Failed transactions** | A failed tx burns one XMSS leaf but does **not** increment the on-chain nonce. Your balance is unaffected; you can retry. |
| **Proof generation** | Sindri runs the circuit in a sandboxed environment. Your private key and raw signature never leave your device. |
| **Quantum resistance** | All on-chain verification relies on SHA-256 hash operations, which are not broken by known quantum algorithms. |

---

## 🧱 Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| **Signature scheme** | XMSS-SHA2_10_256 (NIST SP 800-208) | Post-quantum signing |
| **ZK circuit** | SP1 zkVM (Succinct Labs) | XMSS verification in RISC-V zkVM |
| **ZK proof format** | Groth16 on BN254 (via Sindri) | Compact 260-byte on-chain proof |
| **Smart contract** | Soroban (Stellar) | On-chain proof verification + XLM transfer |
| **CLI** | Rust + Clap + Ratatui | Command-line interface & TUI |
| **Browser extension** | Chrome MV3 · React · TypeScript · Vite | Web UI for casual users |
| **Relay server** | Node.js · Docker | Bypasses Stellar RPC BN254 simulation limit |
| **Network** | Stellar testnet | Live deployment target |

---

## 📂 Repository Structure

```
nebulav2/
├── cli/          # Rust CLI binary (nebula command) + TUI
├── sp1/          # SP1 zkVM circuit — XMSS-SHA2_10_256 verifier
├── soroban/      # Soroban smart contract — Groth16 verifier + XLM transfer
├── xmss/         # XMSS keygen + signing tool
├── xmss-wasm/    # XMSS compiled to WebAssembly (browser extension)
├── extension/    # Chrome MV3 browser extension (React + TypeScript)
├── relayer/      # Node.js relay server (Docker)
├── docs/         # 📚 Documentation for all audiences
├── ARCHITECTURE.md
├── DEVLOG.md
└── install.sh
```

---

<div align="center">

**Built with ❤️ for a quantum-safe future**

[Architecture](./ARCHITECTURE.md) · [Non-Technical Guide](./docs/NON_TECHNICAL_GUIDE.md) · [Technical Reference](./docs/TECHNICAL_REFERENCE.md) · [Developer Guide](./docs/DEVELOPER_GUIDE.md) · [Dev Log](./DEVLOG.md)

</div>
