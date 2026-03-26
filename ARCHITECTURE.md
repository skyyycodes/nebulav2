<div align="center">

# 🌌 Nebula — Architecture Reference

**XMSS Post-Quantum Wallet · SP1 zkVM · Groth16 · Soroban**

</div>

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Component Map](#2-component-map)
3. [Transaction Lifecycle](#3-transaction-lifecycle)
4. [XMSS Signing Layer](#4-xmss-signing-layer)
5. [ZK Proof Layer — SP1 Circuit](#5-zk-proof-layer--sp1-circuit)
6. [Cloud Proving — Sindri](#6-cloud-proving--sindri)
7. [Smart Contract — Soroban](#7-smart-contract--soroban)
8. [CLI Orchestration](#8-cli-orchestration)
9. [Browser Extension](#9-browser-extension)
10. [Relay Server](#10-relay-server)
11. [Data Formats](#11-data-formats)
12. [Security Properties](#12-security-properties)
13. [Design Decisions & Trade-offs](#13-design-decisions--trade-offs)

---

## 1. System Overview

Nebula is a **post-quantum smart wallet** on Stellar. The core security guarantee is:

> *"No classical asymmetric cryptography (ECDSA/ed25519) is used in the signing path. All on-chain authentication is via XMSS signatures, verified via a zero-knowledge proof."*

```mermaid
flowchart LR
    subgraph User["👤 User Layer"]
        CLI["⚙️ Nebula CLI"]
        EXT["🌐 Browser\nExtension"]
        TUI["📺 TUI Dashboard"]
    end

    subgraph Local["🖥️ Local Cryptography"]
        XMSS["🔑 XMSS Tool\nHash-based PQ signing"]
        KEY[("🗄️ key.json\nXMSS keypair")]
    end

    subgraph Proving["☁️ Zero-Knowledge Proving"]
        SINDRI["🧮 Sindri\nCloud Prover"]
        SP1["📐 SP1 zkVM\nRISC-V circuit"]
    end

    subgraph Blockchain["🔗 Stellar Blockchain"]
        RELAY["🔀 Relay Server\n(BN254 bypass)"]
        CONTRACT["📜 Soroban Contract\nGroth16 verification"]
        LEDGER[("📒 Stellar Ledger")]
    end

    CLI --> XMSS
    EXT --> XMSS
    TUI --> CLI
    XMSS <--> KEY
    CLI --> SINDRI
    EXT --> SINDRI
    SINDRI --> SP1
    SP1 --> SINDRI
    SINDRI --> CLI
    CLI --> RELAY
    RELAY --> CONTRACT
    EXT --> RELAY
    CONTRACT --> LEDGER

    style User fill:#1a1a2e,stroke:#7B2FBE,color:#e0e0e0
    style Local fill:#16213e,stroke:#4a90d9,color:#e0e0e0
    style Proving fill:#0f2a1e,stroke:#00C7B7,color:#e0e0e0
    style Blockchain fill:#2a1a0e,stroke:#F46623,color:#e0e0e0
```

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Quantum adversary (Shor's algorithm) | XMSS signatures — only SHA-256 internally, not broken by quantum |
| Replay attacks | On-chain wallet nonce, embedded in `tx_bytes` and committed in ZK proof |
| Key leakage during proving | Private key never sent to Sindri; only `proof_inputs.json` leaves device |
| Signature forgery | Groth16 proof binding to `pubkey_hash` — forging requires breaking SHA-256 |
| Contract manipulation | Hardcoded verification key in Soroban contract — immutable post-deploy |

---

## 2. Component Map

```mermaid
graph TB
    subgraph CLI_Module["CLI Module — cli/"]
        MAIN["main.rs\n1,113 lines\nOrchestrates all components"]
        TUI_SRC["tui.rs\n529 lines\nRatatui dashboard"]
    end

    subgraph XMSS_Module["XMSS Module — xmss/"]
        XMSS_BIN["main.rs\nkeygen · sign · verify"]
    end

    subgraph WASM_Module["XMSS-WASM Module — xmss-wasm/"]
        WASM_LIB["lib.rs\nCompiles XMSS to WebAssembly\nfor browser extension"]
    end

    subgraph SP1_Module["SP1 Module — sp1/"]
        SP1_PROG["program/main.rs\n245 lines\nXMSS verifier circuit (no_std)"]
        SP1_SCRIPT["script/submit.rs\ngen_stdin.rs\nLocal proving helper"]
    end

    subgraph Soroban_Module["Soroban Module — soroban/"]
        CONTRACT_SRC["lib.rs\n473 lines\nGroth16 verifier + XLM transfer"]
    end

    subgraph Extension_Module["Extension Module — extension/"]
        BG["background.ts\nService worker\nProof submission"]
        POPUP["popup.tsx\nReact UI"]
        CRYPTO_TS["crypto.ts\nKey serialization"]
    end

    subgraph Relayer_Module["Relayer Module — relayer/"]
        SERVER["server.js\nNode.js relay\nBN254 simulation bypass"]
    end

    MAIN -->|"spawns"| XMSS_BIN
    MAIN -->|"HTTP REST"| SINDRI_CLOUD(("☁️ Sindri"))
    MAIN -->|"stellar CLI"| RELAY_SVC(("🔀 Relay"))
    POPUP --> BG
    BG -->|"WASM"| WASM_LIB
    BG -->|"HTTP REST"| SINDRI_CLOUD
    BG -->|"HTTP POST"| RELAY_SVC
    RELAY_SVC -->|"stellar contract invoke"| STELLAR_CONTRACT(("�� Soroban"))
    SP1_PROG -->|"ELF uploaded to"| SINDRI_CLOUD
    CONTRACT_SRC -->|"deployed to"| STELLAR_CONTRACT
```

### Component Responsibilities

| Component | Language | Role |
|-----------|----------|------|
| `cli/` | Rust | User-facing command-line interface; orchestrates all other components |
| `xmss/` | Rust | XMSS key generation, signing, local verification |
| `xmss-wasm/` | Rust → WASM | XMSS compiled to WebAssembly for browser |
| `sp1/program/` | Rust (no_std) | zkVM circuit — implements XMSS-SHA2_10_256 verification |
| `sp1/script/` | Rust | Helper scripts for local proving (development) |
| `soroban/` | Rust (no_std) | On-chain smart contract — Groth16 verify + XLM transfer |
| `extension/` | TypeScript + React | Chrome MV3 browser extension |
| `relayer/` | Node.js | Relay server bypassing Stellar testnet BN254 simulation limitation |

---

## 3. Transaction Lifecycle

### 3.1 Key Generation (one-time)

```mermaid
flowchart LR
    A(["▶ nebula wallet create"])
    B["xmss keygen\n(RFC 8391)"]
    C[/"key.json\npublic_key: hex 68B\nsecret_key: hex\nnext_index: 0"/]
    D["sha256(public_key)"]
    E[/"pubkey_hash\n32 bytes\n= wallet identity"/]

    A --> B --> C --> D --> E

    style A fill:#7B2FBE,color:#fff
    style E fill:#00C7B7,color:#000
```

### 3.2 Funding

```mermaid
flowchart LR
    A(["▶ nebula fund --amount 100"])
    B["stellar contract invoke\ndeposit()"]
    C{"Standard\nSoroban auth"}
    D["balance[pubkey_hash]\n+= amount_stroops"]

    A --> B --> C --> D

    style A fill:#7B2FBE,color:#fff
    style D fill:#F46623,color:#fff
```

### 3.3 Withdrawal — Full 4-Stage Pipeline

```mermaid
flowchart TD
    START(["▶ nebula withdraw\n--to GDEST --amount 10"])

    subgraph Stage1["⬡ Stage 1 · Build tx_bytes"]
        Q1["Query contract:\nnonce(pubkey_hash)"]
        B1["Build 108-byte tx_bytes\ncontract_id ║ pubkey_hash ║ nonce\n║ destination ║ amount"]
    end

    subgraph Stage2["⬡ Stage 2 · XMSS Sign (Local)"]
        S1["xmss sign --tx tx_bytes_hex"]
        S2[/"proof_inputs.json\npk_bytes (68B)\ntx_bytes (108B)\nsig_bytes (2500B)\nleaf_index, nonce"/]
    end

    subgraph Stage3["⬡ Stage 3 · ZK Prove (Cloud ~30-60s)"]
        P1["POST /prove to Sindri\nSP1Stdin payload"]
        P2["SP1 zkVM runs:\nXMSS verification circuit"]
        P3["Wrap in Groth16 (BN254)"]
        P4[/"groth16_proof.json\nproof_bytes (260B)\npublic_values (68B)"/]
    end

    subgraph Stage4["⬡ Stage 4 · Submit On-Chain"]
        C1["stellar contract invoke\nwithdraw(proof, pv, dest, amount)"]
        C2{"Soroban Contract\nValidation"}
        C3["✅ XLM transferred\nnonce++"]
    end

    START --> Stage1
    Q1 --> B1
    Stage1 --> Stage2
    S1 --> S2
    Stage2 --> Stage3
    P1 --> P2 --> P3 --> P4
    Stage3 --> Stage4
    C1 --> C2 --> C3

    style START fill:#7B2FBE,color:#fff
    style C3 fill:#00C7B7,color:#000
    style Stage1 fill:#1a1a2e,stroke:#7B2FBE,color:#e0e0e0
    style Stage2 fill:#1a2e1a,stroke:#4CAF50,color:#e0e0e0
    style Stage3 fill:#2e1a1a,stroke:#FF5722,color:#e0e0e0
    style Stage4 fill:#1a1a2e,stroke:#2196F3,color:#e0e0e0
```

### 3.4 On-Chain Validation (Soroban Contract Logic)

```mermaid
flowchart TD
    IN["withdraw(proof_bytes, public_values,\ndestination, amount)"]
    
    V1["Parse public_values (68B):\n→ pubkey_hash (32B)\n→ tx_hash (32B)\n→ wallet_nonce (4B)"]
    
    V2{"nonce ==\nstorage.nonce[pubkey_hash]?"}
    
    V3["Recompute tx_bytes\nfrom contract args"]
    
    V4{"sha256(tx_bytes)\n== tx_hash?"}
    
    V5["Verify Groth16 proof\nBN254 pairing check\nvs hardcoded VK"]
    
    V6{"Proof\nvalid?"}
    
    V7["Transfer XLM\nto destination"]
    
    V8["storage.nonce++ \nEmit WithdrawEvent"]
    
    ERR1(["❌ Error: NonceReplay"])
    ERR2(["❌ Error: TxHashMismatch"])
    ERR3(["❌ Error: InvalidProof"])
    OK(["✅ Success"])

    IN --> V1 --> V2
    V2 -->|"✓ match"| V3
    V2 -->|"✗ mismatch"| ERR1
    V3 --> V4
    V4 -->|"✓ match"| V5
    V4 -->|"✗ mismatch"| ERR2
    V5 --> V6
    V6 -->|"✓ valid"| V7 --> V8 --> OK
    V6 -->|"✗ invalid"| ERR3

    style IN fill:#2196F3,color:#fff
    style OK fill:#00C7B7,color:#000
    style ERR1 fill:#FF5722,color:#fff
    style ERR2 fill:#FF5722,color:#fff
    style ERR3 fill:#FF5722,color:#fff
```

---

## 4. XMSS Signing Layer

### 4.1 Algorithm Overview — XMSS-SHA2_10_256

XMSS (eXtended Merkle Signature Scheme, RFC 8391 / NIST SP 800-208) is a stateful hash-based signature scheme. It builds a Merkle tree of WOTS+ one-time signatures.

```mermaid
graph TB
    subgraph XMSS_Tree["XMSS Merkle Tree — h=10, 1024 leaves"]
        ROOT["🌳 Root (32 bytes)\n= public key"]
        
        N0["Node[0,9]"]
        N1["Node[1,9]"]
        
        L0["Leaf 0\nWOTS+ pub key"]
        L1["Leaf 1\nWOTS+ pub key"]
        LDOTS["..."]
        L1023["Leaf 1023\nWOTS+ pub key"]
        
        ROOT --- N0
        ROOT --- N1
        N0 --- L0
        N0 --- L1
        N1 --- LDOTS
        N1 --- L1023
    end

    subgraph Signing["Signing with leaf i"]
        MSG["tx_bytes (108B)"]
        HMSG["h_msg(r, root, i, tx_bytes)"]
        WOTS["WOTS+ signature\n67 × 32 bytes"]
        AUTH["Auth path\n10 × 32 bytes\n(sibling nodes)"]
        SIG["Signature (2500B)\nidx(4) ║ r(32) ║ WOTS(2144) ║ auth(320)"]
    end

    MSG --> HMSG --> WOTS
    L0 --> AUTH
    WOTS --> SIG
    AUTH --> SIG

    style XMSS_Tree fill:#1a2e1a,stroke:#4CAF50,color:#e0e0e0
    style Signing fill:#1a1a2e,stroke:#7B2FBE,color:#e0e0e0
```

### 4.2 Key & Signature Byte Formats

**Public Key — 68 bytes:**

```
Offset  Size  Content
  0       4   OID (Algorithm identifier)
  4      32   Root node of Merkle tree
 36      32   Public seed (used in WOTS+ hash functions)
```

**Signature — 2500 bytes:**

```
Offset  Size  Content
  0       4   Leaf index (u32 LE) — which one-time key was used
  4      32   r — randomness for h_msg computation
 36    2144   WOTS+ signature (67 chains × 32 bytes each)
2180     320   Authentication path (10 nodes × 32 bytes each)
```

### 4.3 Key State Management

```mermaid
stateDiagram-v2
    [*] --> Fresh: xmss keygen
    Fresh --> Signing: sign tx_bytes
    Signing --> Signing: next_index++\n(updates key.json)
    Signing --> Exhausted: next_index == 1024
    Exhausted --> [*]: Generate new wallet\nMigrate funds
    
    note right of Signing: Each withdrawal\nconsumes 1 leaf.\nLeaf consumed even\nif tx fails on-chain.
```

---

## 5. ZK Proof Layer — SP1 Circuit

### 5.1 Circuit Architecture

The SP1 guest program (`sp1/program/src/main.rs`) implements XMSS verification inside a RISC-V zkVM. This means the Groth16 proof mathematically certifies that the circuit executed correctly — i.e., that a valid XMSS signature was verified.

```mermaid
flowchart TD
    subgraph Private["🔒 Private Inputs (never on-chain)"]
        PK["pk_bytes\n68 bytes\nXMSS public key"]
        TX["tx_bytes\n108 bytes\nTransaction data"]
        SIG["sig_bytes\n2500 bytes\nXMSS signature"]
    end

    subgraph Circuit["⚙️ SP1 zkVM Circuit — RISC-V"]
        C1["Parse signature:\nidx, r, wots_sig, auth_path"]
        C2["Compute h_msg\n= H(r ║ root ║ idx ║ tx_bytes)"]
        C3["For each WOTS+ chain (67×):\nRecover pub key element\nvia wots_chain()"]
        C4["L-tree compression\n67 pub key elements → leaf"]
        C5["Auth path traversal\n10 levels → root"]
        C6{"computed_root\n== pk_bytes.root?"}
        FAIL(["🚫 Circuit HALT\n(proof cannot be generated)"])
    end

    subgraph Public["📢 Public Outputs (on-chain)"]
        OUT1["pubkey_hash\n= sha256(pk_bytes)\n32 bytes"]
        OUT2["tx_hash\n= sha256(tx_bytes)\n32 bytes"]
        OUT3["wallet_nonce\n= tx_bytes[64..68] as u32 LE\n4 bytes"]
    end

    PK --> C1
    TX --> C1
    SIG --> C1
    C1 --> C2 --> C3 --> C4 --> C5 --> C6
    C6 -->|"✗ mismatch"| FAIL
    C6 -->|"✓ match"| OUT1
    C6 -->|"✓ match"| OUT2
    C6 -->|"✓ match"| OUT3
    PK --> OUT1
    TX --> OUT2
    TX --> OUT3

    style Private fill:#2e1a1a,stroke:#FF5722,color:#e0e0e0
    style Circuit fill:#1a1a2e,stroke:#7B2FBE,color:#e0e0e0
    style Public fill:#0f2a1e,stroke:#00C7B7,color:#e0e0e0
```

### 5.2 SHA-256 Operation Count

| Operation | SHA-256 calls |
|-----------|-------------|
| `h_msg` computation | ~3 |
| WOTS+ chain (per element, 67 elements) | ~15 avg |
| L-tree compression | ~66 |
| Auth path traversal | 10 |
| **Total (approximate)** | **~1,000–1,200** |

This is why XMSS was chosen over SPHINCS+ (17,000+ calls) or Falcon (FFI/RAM issues). See [`DEVLOG.md`](./DEVLOG.md) for the full story.

---

## 6. Cloud Proving — Sindri

### 6.1 API Flow

```mermaid
sequenceDiagram
    participant CLI as Nebula CLI
    participant Sindri as Sindri API
    participant SP1 as SP1 Circuit Runner

    CLI->>Sindri: POST /circuit/{id}/prove<br/>{ proof_input: SP1Stdin JSON }
    Sindri-->>CLI: { proof_id: "abc-123" }
    
    loop Poll every 30s
        CLI->>Sindri: GET /proof/abc-123/detail
        Sindri-->>CLI: { status: "Queued" | "InProgress" | "Ready" }
    end
    
    Note over Sindri,SP1: Sindri runs SP1 zkVM<br/>internally on the ELF
    Sindri->>SP1: Execute XMSS circuit
    SP1-->>Sindri: SP1 proof
    Note over Sindri: Wrap SP1 proof in<br/>Groth16 (BN254)
    
    Sindri-->>CLI: { status: "Ready",<br/>  proof: { proof: base64_msgpack } }
    Note over CLI: Decode msgpack →<br/>proof_bytes (260B)<br/>public_values (68B)
```

### 6.2 SP1Stdin Encoding

The circuit input must be encoded as `SP1Stdin` (SP1's standard input format):

```json
{
  "buffer": [
    [8-byte LE length prefix] + [pk_bytes (68B)],
    [8-byte LE length prefix] + [tx_bytes (108B)],
    [8-byte LE length prefix] + [sig_bytes (2500B)]
  ],
  "ptr": 0,
  "proofs": []
}
```

Each field is prefixed with its length as a little-endian `u64` (bincode `Vec<u8>` encoding).

### 6.3 Proof Output Format

The Sindri response's `proof.proof` is **base64-encoded msgpack**:

```
[[{"Groth16": [
  [pub_input_0_decimal, pub_input_1_decimal],
  enc_proof_hex_256_bytes,
  raw_proof_hex,
  vkey_hash_32_bytes
]}]]
```

The CLI extracts:
- **`proof_bytes`** (260 bytes): 4-byte discriminant + 256-byte Groth16 proof (A||B||C on BN254)
- **`public_values`** (68 bytes): pubkey_hash(32) + tx_hash(32) + wallet_nonce(4)

---

## 7. Smart Contract — Soroban

### 7.1 Contract API

```mermaid
classDiagram
    class XmssWallet {
        +init(vkey: BytesN32, xlm_sac: Address)
        +deposit(from: Address, pubkey_hash: BytesN32, amount: i128)
        +withdraw(proof_bytes: Bytes, public_values: Bytes, destination: Address, amount: i128)
        +balance(pubkey_hash: BytesN32) i128
        +nonce(pubkey_hash: BytesN32) u32
    }

    class Storage {
        ProgramVKey: BytesN32
        XlmToken: Address
        Balance_pkh: i128
        Nonce_pkh: u32
    }

    XmssWallet ..> Storage : reads/writes
```

### 7.2 Storage Layout

| Key | Type | Lifetime | Description |
|-----|------|----------|-------------|
| `DataKey::ProgramVKey` | `BytesN<32>` | Instance | SP1 program verification key hash |
| `DataKey::XlmToken` | `Address` | Instance | XLM Stellar Asset Contract address |
| `DataKey::Balance(pk_hash)` | `i128` | Persistent | Balance in stroops (1 XLM = 10,000,000 stroops) |
| `DataKey::Nonce(pk_hash)` | `u32` | Persistent | Monotonically increasing replay counter |

### 7.3 Groth16 Verification (BN254)

The contract uses Soroban's native BN254 pairing host functions. The verification key is hardcoded from `sp1-contracts/v4.0.0-rc.3` byte arrays.

```
Pairing check (Groth16):
e(A, B) == e(alpha, beta) · e(vk_sum, gamma) · e(C, delta)

where:
  A, B, C     = proof points from proof_bytes
  alpha, beta = fixed VK elements (hardcoded)
  gamma, delta = fixed VK elements (hardcoded)
  vk_sum      = VK_IC[0] + pub_input_0·VK_IC[1] + pub_input_1·VK_IC[2]
  pub_inputs  = [program_vkey_hash, committed_values_digest]
```

### 7.4 tx_bytes Construction (108 bytes)

The contract's `build_tx_bytes` helper constructs the 108-byte transaction payload:

```
Offset  Size  Content
  0      32   contract_address encoded (XDR slice [4..36])
 32      32   pubkey_hash (sha256 of XMSS public key)
 64       4   wallet_nonce (u32 LE)
 68      32   destination_address encoded (XDR slice [4..36])
100       8   amount_stroops (i64 LE)
```

> The CLI must replicate this encoding exactly for `sha256(tx_bytes) == tx_hash` to match.

---

## 8. CLI Orchestration

### 8.1 Command Flow

```mermaid
flowchart LR
    subgraph Commands
        WC["wallet create"]
        WI["wallet info"]
        FUND["fund"]
        PROVE["prove"]
        SUBMIT["submit"]
        WITHDRAW["withdraw"]
        UI["ui"]
    end

    subgraph Actions
        KEYGEN["spawn xmss keygen"]
        RPC1["Soroban RPC\nbalance + nonce"]
        RPC2["Soroban RPC\ndeposit()"]
        SIGN["spawn xmss sign"]
        SINDRI_CALL["Sindri REST API\nprove + poll"]
        STELLAR["stellar CLI\nwithdraw()"]
        TUI_LAUNCH["Launch Ratatui TUI"]
    end

    WC --> KEYGEN
    WI --> RPC1
    FUND --> RPC2
    PROVE --> SIGN --> SINDRI_CALL
    SUBMIT --> STELLAR
    WITHDRAW --> SIGN
    WITHDRAW --> SINDRI_CALL
    WITHDRAW --> STELLAR
    UI --> TUI_LAUNCH
```

### 8.2 Environment Configuration (Baked into Binary)

| Variable | Description |
|----------|-------------|
| `WALLET_CONTRACT_ID` | Soroban contract address (`C...`) |
| `WALLET_CONTRACT_HASH` | 32-byte inner hash of contract (hex) |
| `SINDRI_API_KEY` | Sindri API key |
| `STELLAR_ACCOUNT` | Stellar account alias (default: `quantum-deployer`) |

### 8.3 Address Encoding

Stellar addresses must be encoded into `tx_bytes` exactly as the Soroban contract does via `address.to_xdr(env).slice(4..36)`:

| Address type | Encoding |
|-------------|----------|
| Contract (`C...`) | `[0,0,0,1]` (4B SC_ADDRESS discriminant) + `hash[0..28]` (28B) |
| Account (`G...`) | `[0,0,0,0,0,0,0,0]` (8B discriminants) + `key[0..24]` (24B) |

---

## 9. Browser Extension

### 9.1 Architecture

```mermaid
flowchart TD
    subgraph Extension["Chrome MV3 Extension"]
        POPUP_UI["popup.tsx\nReact UI\nbalance · send form\ntx status"]
        BG_SW["background.ts\nService Worker\nIndexedDB storage\nProof orchestration"]
        CRYPTO_MOD["crypto.ts\nKey serialization\nBase64 helpers"]
        WASM_MOD["xmss-wasm\n(compiled .wasm)\nXMSS keygen + sign"]
    end

    USER["👤 User"]
    SINDRI_API["☁️ Sindri API"]
    RELAY_SERVER["🔀 Relay Server"]

    USER --> POPUP_UI
    POPUP_UI <-->|"Chrome message\npassing"| BG_SW
    BG_SW --> CRYPTO_MOD
    BG_SW --> WASM_MOD
    BG_SW -->|"POST /prove"| SINDRI_API
    BG_SW -->|"POST /relay"| RELAY_SERVER

    style Extension fill:#1a1a2e,stroke:#7B2FBE,color:#e0e0e0
```

### 9.2 Key Storage

Keys are stored in **IndexedDB** inside the extension's service worker context. The XMSS key material (including `next_index`) is persisted across browser sessions.

### 9.3 WASM Integration

`xmss-wasm` compiles the XMSS Rust crate to WebAssembly using `wasm-pack`. The browser extension loads it via Vite's bundler. As of the latest toolchain, `getrandom 0.4` has native browser support, enabling direct WASM usage without additional polyfills.

---

## 10. Relay Server

### 10.1 Purpose & Architecture

Stellar's public testnet RPC (`horizon-testnet.stellar.org`) does **not** enable BN254 pairing host functions in simulation mode. The relay server works around this by invoking the `stellar` CLI locally, which runs the contract in a WASM VM with BN254 support enabled.

```mermaid
flowchart LR
    CLIENT["CLI or\nBrowser Extension"]
    
    subgraph Docker["🐳 Docker Container"]
        RELAY_JS["server.js\nNode.js HTTP server\n:3000"]
        STELLAR_CLI["stellar CLI\n(locally installed)"]
    end

    TESTNET["🔗 Stellar\nTestnet RPC"]

    CLIENT -->|"POST /relay\n{ proof_bytes,\npublic_values,\ndestination,\namount }"| RELAY_JS
    RELAY_JS -->|"stellar contract invoke\nwithdraw(...)"| STELLAR_CLI
    STELLAR_CLI -->|"signed tx"| TESTNET
    TESTNET -->|"tx hash"| STELLAR_CLI
    STELLAR_CLI --> RELAY_JS
    RELAY_JS -->|"{ txHash }"| CLIENT
```

### 10.2 Relay Request Format

```json
{
  "proof_bytes": "<hex, 260 bytes>",
  "public_values": "<hex, 68 bytes>",
  "destination": "GDEST...ADDR",
  "amount_stroops": 100000000
}
```

---

## 11. Data Formats

### 11.1 key.json

```json
{
  "algorithm": "XMSS-SHA2_10_256",
  "public_key": "<hex, 68 bytes>",
  "secret_key": "<hex, large>",
  "next_index": 0
}
```

⚠️ `next_index` is incremented after every signing operation and written back immediately to prevent key reuse. Never modify this value manually — doing so can cause XMSS one-time keys to be reused, breaking the security guarantees of the signature scheme.

### 11.2 proof_inputs.json

```json
{
  "public_key": "<hex, 68 bytes>",
  "tx_bytes": "<hex, 108 bytes>",
  "signature": "<hex, 2500 bytes>",
  "leaf_index": 0,
  "nonce": 0
}
```

### 11.3 groth16_proof.json

```json
{
  "proof_bytes": "<hex, 260 bytes>",
  "public_values": "<hex, 68 bytes>"
}
```

### 11.4 public_values (68 bytes) layout

```
Offset  Size  Content
  0      32   pubkey_hash = sha256(XMSS public key)
 32      32   tx_hash     = sha256(tx_bytes)
 64       4   wallet_nonce = u32 LE
```

---

## 12. Security Properties

### 12.1 Post-Quantum Security

| Property | Achieved by |
|----------|------------|
| **Signing key** never exposed | XMSS private key stays in `key.json` on user's machine |
| **Quantum-resistant authentication** | XMSS relies only on SHA-256; not broken by Shor's or Grover's algorithms |
| **Signature non-forgery** | XMSS one-time keys: each leaf used at most once, Merkle tree binding |
| **ZK proof binding** | Groth16 proof commits to `pubkey_hash` and `tx_hash` — cannot reuse proof for different tx |

### 12.2 Replay Protection

```mermaid
flowchart LR
    A["XMSS leaf index\n(local state in key.json)"] 
    B["wallet_nonce\n(on-chain storage)"]
    
    NOTE1["Tracks: how many signing\noperations have occurred.\nBurned even on failed tx."]
    NOTE2["Tracks: how many\nsuccessful withdrawals.\nOnly incremented\non successful tx."]
    
    A --> NOTE1
    B --> NOTE2
```

These two counters are **intentionally decoupled**. A failed on-chain transaction burns a WOTS+ leaf (advances `leaf_index`) but does **not** increment `wallet_nonce`. This means you can retry a failed transaction by re-signing with a new leaf — your balance is unaffected.

### 12.3 Proof Freshness

The `tx_hash = sha256(tx_bytes)` committed in the proof binds the proof to:
- A specific contract address
- A specific sender (`pubkey_hash`)
- A specific `wallet_nonce` (prevents replaying old proofs)
- A specific destination and amount

A proof generated for nonce `N` cannot be submitted when the on-chain nonce is `N+1`.

---

## 13. Design Decisions & Trade-offs

### 13.1 Why XMSS over SPHINCS+ or Falcon?

| Scheme | In-Circuit SHA-256 ops | Issues |
|--------|----------------------|--------|
| SPHINCS+ (FIPS 205) | ~17,000 | Prohibitively expensive in ZK |
| Falcon (FIPS 206) | Few | 32GB RAM for keygen; FFI cross-compilation failure |
| **XMSS (NIST SP 800-208)** | **~1,000–1,200** | **Stateful (1024 key limit) — acceptable for testnet** |

### 13.2 Why SP1 over Noir or Risc0?

| System | Decision | Reason |
|--------|----------|--------|
| Noir | Rejected | Couldn't implement custom XMSS circuit efficiently |
| Risc0 | Rejected (v1) | Used earlier; SP1 v4 offered better ecosystem + Sindri support |
| **SP1** | **Chosen** | Standard Rust code in zkVM; Sindri native support; active ecosystem |

### 13.3 Why Sindri over Self-Hosted Proving?

Generating a Groth16 proof for an SP1 RISC-V program requires significant computation (dozens of seconds on powerful hardware). Sindri provides a managed proving service with a REST API, making it accessible without specialized hardware. The trade-off: users need a Sindri API key.

### 13.4 Why a Relay Server?

Stellar's public testnet RPC disables BN254 pairing functions in `simulateTransaction`. The relay server runs a local Stellar CLI with a full node that supports BN254. This is a testnet-specific limitation and would not be required on mainnet.

### 13.5 Why Decouple XMSS leaf index from wallet nonce?

A naive design would use the XMSS leaf index as the on-chain replay counter. However, a failed transaction (e.g., network timeout, insufficient fee) would advance the leaf index but not be committed on-chain — making the wallet nonce out of sync. By embedding a separate `wallet_nonce` in `tx_bytes` (read from on-chain before signing), the system allows retrying with a new leaf without corrupting the replay counter.

---

<div align="center">

**See also:** [Non-Technical Guide](./docs/NON_TECHNICAL_GUIDE.md) · [Technical Reference](./docs/TECHNICAL_REFERENCE.md) · [Developer Guide](./docs/DEVELOPER_GUIDE.md) · [Dev Log](./DEVLOG.md)

</div>
