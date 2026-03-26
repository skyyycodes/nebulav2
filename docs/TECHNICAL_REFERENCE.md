<div align="center">

# 🔬 Nebula — Technical Reference

### Complete specification for developers, auditors, and integrators.

</div>

---

## Table of Contents

1. [Protocol Overview](#1-protocol-overview)
2. [XMSS-SHA2_10_256 Specification](#2-xmss-sha2_10_256-specification)
3. [SP1 zkVM Circuit Specification](#3-sp1-zkvm-circuit-specification)
4. [Groth16 Proof Format](#4-groth16-proof-format)
5. [Soroban Contract API Reference](#5-soroban-contract-api-reference)
6. [tx_bytes Construction](#6-tx_bytes-construction)
7. [Sindri API Integration](#7-sindri-api-integration)
8. [CLI Command Reference](#8-cli-command-reference)
9. [Data Formats & Encodings](#9-data-formats--encodings)
10. [Error Codes & Handling](#10-error-codes--handling)
11. [Cryptographic Constants](#11-cryptographic-constants)

---

## 1. Protocol Overview

Nebula's withdrawal protocol is a **3-party interactive protocol** between:

- **Prover** (user's local machine): holds XMSS private key, signs transactions
- **Verifier-circuit** (SP1 zkVM at Sindri): verifies XMSS signature, commits public values
- **Verifier-contract** (Soroban on Stellar): verifies Groth16 proof, enforces nonce and tx_hash

### Security Assumptions

| Assumption | What it means |
|-----------|--------------|
| **SHA-256 collision resistance** | Attacker cannot find two inputs with the same SHA-256 output |
| **SHA-256 preimage resistance** | Attacker cannot recover XMSS key from `pubkey_hash` |
| **Groth16 soundness (BN254)** | Attacker cannot produce a valid proof without a valid witness |
| **SP1 circuit correctness** | The compiled ELF correctly implements XMSS-SHA2_10_256 |
| **Sindri integrity** | Sindri runs the correct circuit (verifiable by `program_vkey` hash) |

### Protocol Invariants

1. A proof is valid for **exactly one** `(pubkey_hash, tx_hash, wallet_nonce)` triple.
2. `wallet_nonce` increments monotonically — old proofs cannot be replayed.
3. `tx_hash` binds the proof to a specific `(contract, pubkey_hash, nonce, destination, amount)`.
4. An XMSS leaf index, once used, is irrevocable — even on transaction failure.

---

## 2. XMSS-SHA2_10_256 Specification

### Algorithm Parameters

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `h` | 10 | Tree height → 2^10 = 1024 signatures |
| `n` | 32 | Security parameter (bytes) = SHA-256 output size |
| `w` | 16 | Winternitz parameter (chains of length 15) |
| `len` | 67 | WOTS+ chain count (= `len1 + len2 = 64 + 3`) |
| Hash | SHA-256 | Underlying hash function |

### Key Generation

```
Input:  secure random seed
Output: (SK, PK)

PK = (OID || root || pub_seed)  -- 4 + 32 + 32 = 68 bytes
SK = xmss-rs internal format    -- large (tree nodes + state)
```

The **root** is the Merkle tree root computed over 1024 WOTS+ public keys.

### Signature Structure

**Total: 2500 bytes**

```
sig = idx_bytes || r || wots_signature || auth_path

idx_bytes  : 4 bytes  (leaf index, big-endian u32)
r          : 32 bytes (per-signature randomness)
wots_sig   : 2144 bytes (67 chains × 32 bytes)
auth_path  : 320 bytes (10 nodes × 32 bytes)
```

### Verification Algorithm

```
Input:  PK = (oid, root, pub_seed)
        M  = message (tx_bytes)
        sig = (idx, r, wots_sig, auth_path)

1. msg_hash = H_msg(r, root, idx_bytes, M)
              = SHA256(toByte(2,32) || root || pub_seed || idx_bytes
                       || SHA256(toByte(1,32) || pub_seed || idx_bytes || M))

2. For each of 67 WOTS+ chains:
   pk_i = wots_chain(sig_i, ctr, w-1-ctr, pub_seed, ADRS)
   where ctr = base_w(msg_hash)[i]  -- Winternitz checksum

3. leaf = L_tree(pk_0..pk_66, pub_seed, ADRS)

4. node = leaf
   For level k = 0..9:
     auth_k = auth_path[k]
     if idx_bit(k) == 0: node = H(node || auth_k, pub_seed, ADRS_k)
     else:               node = H(auth_k || node, pub_seed, ADRS_k)

5. Assert: node == root
```

### Address (ADRS) Encoding

XMSS uses 32-byte address structures (ADRS) for domain separation in hash calls:

```
ADRS (32 bytes):
  layer_address   : 4 bytes
  tree_address    : 8 bytes
  type            : 4 bytes  (OTS=0, L_TREE=1, HASH_TREE=2)
  ots_address     : 4 bytes
  chain_address   : 4 bytes
  hash_address    : 4 bytes  (or tree_index for hash tree)
  key_and_mask    : 4 bytes
```

---

## 3. SP1 zkVM Circuit Specification

### Source

`sp1/program/src/main.rs` — 245 lines, `#![no_main]`, Rust

### Dependencies

```toml
sp1-zkvm = "4.1.3"
sha2 = { version = "0.10", default-features = false }
```

### Private Inputs (SP1Stdin)

Read via `sp1_zkvm::io::read::<Vec<u8>>()` (bincode-encoded):

| Order | Field | Size |
|-------|-------|------|
| 1 | `pk_bytes` | 68 bytes |
| 2 | `tx_bytes` | 108 bytes |
| 3 | `sig_bytes` | 2500 bytes |

### Public Outputs (Committed Values)

Written via `sp1_zkvm::io::commit_slice(&bytes)`:

```
public_values (68 bytes):
  pubkey_hash   [0..32]   = sha256(pk_bytes)
  tx_hash       [32..64]  = sha256(tx_bytes)
  wallet_nonce  [64..68]  = u32::from_le_bytes(tx_bytes[64..68])
```

### Circuit Execution Trace

```
1. Read pk_bytes, tx_bytes, sig_bytes from stdin
2. Parse sig_bytes:
     idx       = u32::from_be_bytes(sig_bytes[0..4])
     r         = sig_bytes[4..36]
     wots_sig  = sig_bytes[36..2180]   (67 × 32B)
     auth_path = sig_bytes[2180..2500] (10 × 32B)
3. Extract from pk_bytes:
     root     = pk_bytes[4..36]
     pub_seed = pk_bytes[36..68]
4. Compute h_msg:
     idx_bytes = idx.to_be_bytes()
     inner = sha256([0x01×32] ++ pub_seed ++ idx_bytes ++ tx_bytes)
     msg   = sha256([0x02×32] ++ root ++ pub_seed ++ idx_bytes ++ inner)
5. base_w decomposition of msg → 64 coefficients (msg_bw)
6. Winternitz checksum → 3 more coefficients
7. For i in 0..67:
     start = msg_bw[i] (or checksum coeff)
     steps = (w-1) - start
     pk_i  = wots_chain(wots_sig[i*32..(i+1)*32], start, steps, pub_seed, ADRS_ots)
8. L-tree over pk_0..pk_66 → leaf
9. For level k in 0..10:
     auth_node = auth_path[k*32..(k+1)*32]
     if (idx >> k) & 1 == 0: parent = hash_tree(node, auth_node, ...)
     else:                    parent = hash_tree(auth_node, node, ...)
10. Assert computed_root == root  (panics → proof generation fails)
11. commit pubkey_hash, tx_hash, wallet_nonce
```

### Hash Function Variants Used in Circuit

| Function | Domain Tag | Inputs |
|----------|-----------|--------|
| `prf(seed, adrs)` | `[0x03×32]` | key=seed, msg=adrs |
| `h_msg(r,root,idx,M)` | `[0x02×32]` | see above |
| `f(key, x)` | `[0x00×32]` | key=PRF(pub_seed,adrs), x=msg |
| `h(key, xl, xr)` | `[0x01×32]` | key=PRF(pub_seed,adrs), x=xl||xr |

All are `SHA256(domain_tag || key || message)` variants from RFC 8391 §5.

---

## 4. Groth16 Proof Format

### proof_bytes (260 bytes)

```
Offset  Size  Content
  0       4   Discriminant: [0x00, 0x00, 0x00, 0x01] (Groth16 marker)
  4      64   Point A on G1 (BN254): x(32B LE) || y(32B LE)
 68     128   Point B on G2 (BN254): x_c0(32B) || x_c1(32B) || y_c0(32B) || y_c1(32B)
196      64   Point C on G1 (BN254): x(32B LE) || y(32B LE)
```

### public_values (68 bytes)

```
Offset  Size  Content
  0      32   pubkey_hash  (SHA-256 of XMSS public key)
 32      32   tx_hash      (SHA-256 of tx_bytes)
 64       4   wallet_nonce (u32, little-endian)
```

### Public Inputs to Groth16 (2 field elements on BN254)

The SP1 framework maps `public_values` into two BN254 field elements before calling the pairing:

| Index | Value |
|-------|-------|
| 0 | `program_vkey` — hash of the SP1 circuit ELF (32 bytes, big-endian as Fr) |
| 1 | `committed_values_digest` — SHA-256 of `public_values` (32 bytes, big-endian as Fr) |

---

## 5. Soroban Contract API Reference

### Contract Address

> `CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B` (testnet)

### Functions

#### `init(vkey: BytesN<32>, xlm_sac: Address)`

Initialize the contract. Called once at deployment.

| Parameter | Type | Description |
|-----------|------|-------------|
| `vkey` | `BytesN<32>` | SP1 program verification key hash |
| `xlm_sac` | `Address` | Stellar XLM Stellar Asset Contract address |

Panics if called twice.

---

#### `deposit(from: Address, pubkey_hash: BytesN<32>, amount: i128)`

Deposit XLM into a wallet identified by `pubkey_hash`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `from` | `Address` | Sender's Stellar account (Soroban auth required) |
| `pubkey_hash` | `BytesN<32>` | `sha256(XMSS_public_key)` |
| `amount` | `i128` | Amount in stroops (1 XLM = 10,000,000 stroops) |

Side effects:
- Calls `XLM SAC.transfer(from, contract, amount)`
- Updates `storage.balance[pubkey_hash] += amount`
- Initializes `storage.nonce[pubkey_hash] = 0` if not set

---

#### `withdraw(proof_bytes: Bytes, public_values: Bytes, destination: Address, amount: i128)`

Verify a ZK proof and transfer XLM if valid.

| Parameter | Type | Description |
|-----------|------|-------------|
| `proof_bytes` | `Bytes` | 260-byte Groth16 proof |
| `public_values` | `Bytes` | 68-byte committed values |
| `destination` | `Address` | Recipient Stellar address |
| `amount` | `i128` | Amount in stroops |

Validation steps (all must pass):
1. Parse `public_values` → `pubkey_hash`, `tx_hash`, `wallet_nonce`
2. Assert `wallet_nonce == storage.nonce[pubkey_hash]`
3. Recompute `tx_bytes` from `(contract_address, pubkey_hash, wallet_nonce, destination, amount)`
4. Assert `sha256(tx_bytes) == tx_hash`
5. Verify Groth16 proof against hardcoded BN254 verification key
6. Assert `storage.balance[pubkey_hash] >= amount`
7. Transfer XLM to destination
8. Decrement balance, increment nonce, emit `WithdrawEvent`

Panics (errors):
- `NonceReplay` — nonce mismatch
- `TxHashMismatch` — tx_hash doesn't match reconstructed tx_bytes
- `InvalidProof` — Groth16 pairing check failed
- `InsufficientBalance` — balance < amount

---

#### `balance(pubkey_hash: BytesN<32>) → i128`

Read-only. Returns wallet balance in stroops.

---

#### `nonce(pubkey_hash: BytesN<32>) → u32`

Read-only. Returns current wallet nonce (number of successful withdrawals).

---

### Events

#### `WithdrawEvent`

Emitted on successful withdrawal:

```rust
struct WithdrawEvent {
    pubkey_hash: BytesN<32>,
    destination: Address,
    amount: i128,
    nonce: u32,
}
```

---

## 6. tx_bytes Construction

The 108-byte `tx_bytes` is the signed payload. Both the CLI and contract must construct it identically.

### Layout

```
Offset  Size  Content
  0      32   contract_field  = encode_address(contract_address)
 32      32   pubkey_hash     = sha256(pk_bytes)
 64       4   wallet_nonce    = u32 little-endian
 68      32   dest_field      = encode_address(destination)
100       8   amount          = i64 little-endian (stroops)
```

**Total: 108 bytes**

### Address Encoding — `encode_address(addr)`

The Soroban contract uses `addr.to_xdr(env).slice(4..36)` which produces:

**For Contract addresses (C...):**
```
encode_address(C...) = [0x00, 0x00, 0x00, 0x01] ++ contract_inner_hash[0..28]
```
The `contract_inner_hash` is the 32-byte hash inside the StrKey encoding.

**For Account addresses (G...):**
```
encode_address(G...) = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] ++ ed25519_key[0..24]
```
The `ed25519_key` is the 32-byte raw Ed25519 public key decoded from the StrKey.

> ⚠️ **This encoding is non-obvious.** The CLI's `stellar_to_contract_field` function replicates it exactly. Do not guess — verify against the contract source before integrating.

---

## 7. Sindri API Integration

### Base URL

`https://sindri.app/api/v1`

### Authentication

```http
Authorization: Bearer <SINDRI_API_KEY>
```

### Circuit Information

| Field | Value |
|-------|-------|
| Circuit ID | `675b1311-8e2b-4b2c-9f16-44a548a3e2b7` |
| Circuit type | SP1 |
| Proof system | Groth16 (BN254) |

### Submit Proof Job

**Request:**

```http
POST /api/v1/circuit/{circuit_id}/prove
Content-Type: application/json
Authorization: Bearer {API_KEY}

{
  "proof_input": {
    "buffer": [
      [encoded_pk_bytes],
      [encoded_tx_bytes],
      [encoded_sig_bytes]
    ],
    "ptr": 0,
    "proofs": []
  }
}
```

Each entry in `buffer` is a bincode-encoded `Vec<u8>`: an 8-byte little-endian length prefix followed by the raw bytes.

**Response:**

```json
{
  "proof_id": "abc123-...",
  "status": "Queued"
}
```

### Poll Proof Status

**Request:**

```http
GET /api/v1/proof/{proof_id}/detail
Authorization: Bearer {API_KEY}
```

**Response when ready:**

```json
{
  "status": "Ready",
  "proof": {
    "proof": "<base64-encoded msgpack>"
  }
}
```

**Statuses:** `Queued` → `InProgress` → `Ready` | `Failed`

### Decode Proof Response

The `proof.proof` field is **base64 → msgpack** with structure:

```
[[{"Groth16": [
  [pub_input_0_decimal_string, pub_input_1_decimal_string],
  enc_proof_hex_string,       // 256 bytes: A(64) + B(128) + C(64)
  raw_proof_hex_string,       // full raw proof
  vkey_hash_bytes             // 32 bytes
]}]]
```

**Parsing steps:**

1. Base64-decode `proof.proof`
2. Msgpack-decode the result
3. Extract `enc_proof` (256 bytes) and `vkey_hash` (32 bytes)
4. Convert `pub_input_0` from decimal string to 32-byte big-endian hex
5. Construct `proof_bytes = [0,0,0,1] ++ enc_proof[0..256]` (260 bytes total)
6. Construct `public_values` from circuit commits (68 bytes)

---

## 8. CLI Command Reference

### `nebula wallet create`

Calls `xmss keygen`, writes `key.json`. Displays `pubkey_hash` (wallet identity).

### `nebula wallet info`

Calls contract `balance(pubkey_hash)` and `nonce(pubkey_hash)` via Soroban RPC. Displays remaining XMSS keys.

### `nebula fund --amount <XLM>`

Calls `contract.deposit(from, pubkey_hash, amount_stroops)` via `stellar contract invoke`.

### `nebula intent --destination <G...> --amount <XLM>`

Displays the `tx_bytes` (hex) that would be signed, for inspection without committing a signing key.

### `nebula prove`

1. Reads `key.json`, queries nonce
2. Builds `tx_bytes`
3. Calls `xmss sign`
4. POSTs to Sindri, polls until ready
5. Writes `groth16_proof.json`

### `nebula submit --destination <G...> --amount <XLM>`

Reads `groth16_proof.json`, calls `stellar contract invoke withdraw`.

### `nebula withdraw --to <G...> --amount <XLM>`

Full pipeline: equivalent to `prove` + `submit` in sequence.

### `nebula ui`

Launches Ratatui TUI dashboard.

### Environment Variables (Baked at Compile Time)

| Variable | Description |
|----------|-------------|
| `WALLET_CONTRACT_ID` | `CCQ4R5...` — deployed Soroban contract |
| `WALLET_CONTRACT_HASH` | 32-byte inner hash (hex) of the contract |
| `SINDRI_API_KEY` | Cloud prover API key |
| `STELLAR_ACCOUNT` | Stellar CLI account alias (default: `quantum-deployer`) |

---

## 9. Data Formats & Encodings

### key.json

```json
{
  "algorithm": "XMSS-SHA2_10_256",
  "public_key": "<hex string, 68 bytes>",
  "secret_key": "<hex string, variable length>",
  "next_index": 0
}
```

**Critical:** `next_index` is updated atomically after every sign operation. Never modify this file manually.

### proof_inputs.json

```json
{
  "public_key": "<hex, 68 bytes>",
  "tx_bytes": "<hex, 108 bytes>",
  "signature": "<hex, 2500 bytes>",
  "leaf_index": 0,
  "nonce": 0
}
```

### groth16_proof.json

```json
{
  "proof_bytes": "<hex, 260 bytes>",
  "public_values": "<hex, 68 bytes>"
}
```

### Hex Encoding

All binary data (keys, signatures, proofs) is encoded as lowercase hexadecimal strings without `0x` prefix.

---

## 10. Error Codes & Handling

### Contract Errors (Soroban Panics)

| Error | Cause | Recovery |
|-------|-------|---------|
| `NonceReplay` | `wallet_nonce` in proof ≠ on-chain nonce | Query current nonce, re-sign, re-prove |
| `TxHashMismatch` | `tx_hash` doesn't match recomputed tx_bytes | Verify amount/destination/nonce match proof |
| `InvalidProof` | Groth16 pairing check failed | Re-generate proof; check VK matches deployed contract |
| `InsufficientBalance` | balance < requested amount | Fund the wallet first |
| `AlreadyInitialized` | `init()` called twice | N/A — contract already set up |

### Sindri API Errors

| Status | Cause | Recovery |
|--------|-------|---------|
| `Failed` | Circuit execution error | Check `proof_inputs.json` validity; re-sign |
| HTTP 401 | Invalid API key | Verify `SINDRI_API_KEY` |
| HTTP 429 | Rate limited | Wait and retry |
| Timeout | Network issue | Retry the full `prove` command |

### XMSS Errors

| Error | Cause | Recovery |
|-------|-------|---------|
| Verification failure | Wrong key or corrupted signature | Re-sign with correct `key.json` |
| Index exhausted | `next_index == 1024` | Create new wallet, migrate funds |

---

## 11. Cryptographic Constants

### SP1 Circuit VKey Hash

The hash of the SP1 program ELF, used as `pub_input_0` in Groth16:

```
program_vkey = [see groth16_proof.json pub_input_0 field]
```

This must match `DataKey::ProgramVKey` in the deployed Soroban contract.

### BN254 Curve Parameters

```
Field modulus p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Scalar field r  = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

### Deployed Contract

| Network | Contract ID |
|---------|------------|
| Stellar Testnet | `CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B` |

---

<div align="center">

**See also:** [Architecture Guide](../ARCHITECTURE.md) · [Developer Guide](./DEVELOPER_GUIDE.md) · [Non-Technical Guide](./NON_TECHNICAL_GUIDE.md)

</div>
