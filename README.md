# nebula

A post-quantum wallet for Stellar. Send XLM using XMSS signatures verified on-chain via a ZK proof — no classical cryptography in the signing path.
<img width="1406" height="1021" alt="nebula-architecture drawio" src="https://github.com/user-attachments/assets/9cf3df54-0fb3-424e-85cf-432ab8e2c1b1" />

```
XMSS sign → SP1 ZK proof → Groth16 (Sindri) → Soroban contract → XLM transfer
```

> Running on Stellar testnet. Contract: `CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B`

---

## Install

**Linux / macOS — one line:**

```bash
curl -fsSL https://raw.githubusercontent.com/Eshan276/nebulav2/main/install.sh | bash
```

This downloads the pre-built binary for your platform (Linux x86\_64, macOS ARM, macOS x86\_64) and installs it to `~/.local/bin`.

If `~/.local/bin` is not in your PATH, add this to `~/.bashrc` or `~/.zshrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell:

```bash
source ~/.bashrc   # or ~/.zshrc
```

Verify the install:

```bash
nebula --help
```

No `.env` file needed — all configuration is baked into the binary.

---

## Usage

### Create a wallet

```bash
nebula wallet create
```

Generates your XMSS keypair and saves it to `key.json` in the current directory.
**Back this file up — if you lose it, you lose access to your wallet.**

### Check balance and nonce

```bash
nebula wallet info
```

### Fund your wallet

```bash
nebula fund --amount 100
```

Deposits 100 XLM from your Stellar account into your XMSS wallet contract.

### Send XLM

```bash
nebula withdraw --to GDEST...ADDR --amount 10
```

Signs with your XMSS key locally, generates a ZK proof (~30–60s), and submits on-chain.

### Interactive terminal UI

```bash
nebula ui
```

Dashboard showing balance, nonce, XMSS keys remaining, and an interactive send wizard.

---

## How it works

1. **XMSS signing** — your private key signs the transaction locally. The key never leaves your machine.
2. **ZK proof** — SP1 proves inside a zkVM circuit that a valid XMSS signature exists over the transaction. Compiled to a Groth16 proof via Sindri.
3. **On-chain verification** — the Soroban contract verifies the Groth16 proof, checks the public key hash and nonce, and transfers XLM atomically.

The contract never sees your private key or signature — only a mathematical proof that they existed.

### Why post-quantum?

XMSS (NIST SP 800-208) is a hash-based signature scheme. Unlike ed25519/ECDSA, it is not broken by Shor's algorithm. Your funds remain secure even against a quantum adversary.

### XMSS key limits

`SHA2_10_256` gives you **1024 one-time signing keys**. Each withdrawal uses one. The UI shows how many you have left. When exhausted, generate a new wallet and migrate funds with a standard withdrawal.

---

## Security notes

- `key.json` is your private key — keep it safe, do not commit it, do not upload it to cloud storage unencrypted
- Failed transactions burn one XMSS leaf but do **not** increment the on-chain nonce — your balance is unaffected and you can retry
- Proof generation uses Sindri's cloud infrastructure — your key and signature never leave your device

---

## Stack

| Component | Technology |
|---|---|
| Signature scheme | XMSS-SHA2_10_256 (NIST SP 800-208 / RFC 8391) |
| ZK proving | SP1 (Succinct) + Groth16 via Sindri |
| Smart contract | Soroban (Stellar) with BN254 host functions |
| CLI | Rust |
| Network | Stellar testnet |
