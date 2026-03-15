# nebula

A post-quantum wallet for Stellar. Send XLM using XMSS signatures verified on-chain via a ZK proof — no classical cryptography involved in the signing.

```
XMSS sign → SP1 ZK proof → Groth16 (Sindri) → Soroban contract → XLM transfer
```

> Running on Stellar testnet. Contract: `CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B`

---

## Install

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/Eshan276/nebulav2/main/install.sh | bash
```

Then add `~/.local/bin` to your PATH if prompted:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Setup

Create a `.env` file in the directory where you run `nebula`:

```
SINDRI_API_KEY=<your key — ask @Eshan276>
WALLET_CONTRACT_ID=CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B
WALLET_CONTRACT_HASH=a1c8f4b33bc6133d98258838ab2c3d8f86f201d78719e44ce3102046cd5a55df
```

> To get a `SINDRI_API_KEY`, message the repo owner or sign up at [sindri.app](https://sindri.app).

---

## Usage

### Create a wallet
```bash
nebula wallet create
```
Generates your XMSS keypair and saves it to `key.json`. **Back this file up — if you lose it, you lose access to your wallet.**

### Check balance
```bash
nebula wallet info
```

### Fund your wallet
```bash
nebula fund --amount 100
```
Deposits 100 XLM into your XMSS wallet contract.

### Withdraw / Send XLM
```bash
nebula withdraw --to GDEST...ADDR --amount 10
```
Signs the transaction with your XMSS key, generates a ZK proof (~30-60s via Sindri), and submits it on-chain.

### Interactive UI
```bash
nebula ui
```
Dashboard view with balance, nonce, XMSS leaf usage, and an interactive send wizard.

---

## How it works

1. **XMSS signing** — your private key signs the transaction locally. The key never leaves your machine.
2. **ZK proof** — SP1 proves inside a circuit that a valid XMSS signature exists over the transaction. Sindri compiles this to a Groth16 proof.
3. **On-chain verification** — the Soroban contract verifies the Groth16 proof and checks the public key hash and nonce before transferring XLM.

The on-chain contract never sees your private key or signature — only the mathematical proof that they existed.

### Why post-quantum?
XMSS is a NIST-standardized hash-based signature scheme. Unlike ECDSA/ed25519, it is not broken by quantum computers (Shor's algorithm). Your funds remain secure even against a quantum adversary.

### XMSS key limits
`SHA2_10_256` gives you **1024 one-time signing keys**. Each withdrawal uses one. The UI shows how many you have left. When exhausted, generate a new wallet and migrate funds.

---

## Security notes

- `key.json` is your private key — keep it safe, don't commit it, don't upload it to cloud storage unencrypted
- Failed transactions (e.g. network errors) burn an XMSS leaf but do NOT increment the nonce — your wallet balance is safe
- The Sindri API key is used only for proof generation — it has no access to your keys or funds

---

## Stack

| Component | Technology |
|---|---|
| Signature scheme | XMSS-SHA2_10_256 (NIST SP 800-208) |
| ZK proving | SP1 (Succinct) + Groth16 via Sindri |
| Smart contract | Soroban (Stellar) |
| CLI | Rust |
| Network | Stellar testnet |b
