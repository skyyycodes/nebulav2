<div align="center">

# 🌌 Nebula — Plain-English Guide

### Everything you need to know to use Nebula, no technical background required.

</div>

---

## Table of Contents

1. [What is Nebula?](#1-what-is-nebula)
2. [Why Does Quantum Computing Matter for Crypto?](#2-why-does-quantum-computing-matter-for-crypto)
3. [How Nebula Keeps You Safe](#3-how-nebula-keeps-you-safe)
4. [Getting Started — Step by Step](#4-getting-started--step-by-step)
5. [Sending and Receiving XLM](#5-sending-and-receiving-xlm)
6. [Using the Dashboard](#6-using-the-dashboard)
7. [Understanding Key Limits](#7-understanding-key-limits)
8. [Frequently Asked Questions](#8-frequently-asked-questions)
9. [Safety Checklist](#9-safety-checklist)

---

## 1. What is Nebula?

**Nebula is a digital wallet for XLM (Stellar Lumens)** — the same as any other crypto wallet, except it's built to stay secure even against quantum computers.

Think of it like this:

> 🔐 A regular crypto wallet is like a padlock that's very hard to pick today.  
> 🛡️ Nebula is like a vault that will *still* be impossible to break open even after quantum computers exist.

### What can you do with Nebula?

| Action | What it means |
|--------|--------------|
| **Create a wallet** | Generate a unique, quantum-safe identity on the Stellar network |
| **Fund your wallet** | Move XLM from a regular Stellar account into your Nebula wallet |
| **Send XLM** | Transfer XLM to anyone on the Stellar network, securely |
| **Check your balance** | See how much XLM you have at any time |

---

## 2. Why Does Quantum Computing Matter for Crypto?

### The current situation

Every crypto wallet today — Bitcoin, Ethereum, Stellar — uses mathematical problems that are **very hard for today's computers** to solve. Your funds are safe because cracking the math would take millions of years on current hardware.

### The quantum threat

Quantum computers work differently. They can solve certain math problems — specifically the ones that protect ECDSA and ed25519 signatures (used by most wallets) — **exponentially faster**.

A powerful enough quantum computer could:
- Derive your private key from your public key
- Sign transactions on your behalf
- Drain your wallet

This isn't science fiction. Nation-states and major tech companies are actively building these machines. The crypto industry is racing to adopt "post-quantum" solutions before that day arrives.

### A simple comparison

```
Regular wallet (ed25519):
  Private key → 🔒 ← Quantum computer can crack this

Nebula (XMSS):
  Private key → 🛡️ ← Only hash functions. Quantum computers
                      cannot break these efficiently.
```

---

## 3. How Nebula Keeps You Safe

Nebula uses three layers of protection working together:

### Layer 1 — XMSS Signatures 🔑

Your wallet uses a technology called **XMSS** (pronounced "ex-muss"). It's a signature scheme approved by the US National Institute of Standards and Technology (NIST) specifically as a quantum-resistant alternative.

Instead of the math that quantum computers can break, XMSS uses only **hash functions** — like SHA-256, the same algorithm used in Bitcoin's proof-of-work. Hash functions are not vulnerable to quantum attacks.

> **In plain terms:** You sign transactions with a key that even quantum computers cannot fake.

### Layer 2 — Zero-Knowledge Proofs 🧮

Here's something remarkable: when you send XLM with Nebula, the blockchain never even sees your signature. Instead, it sees a **mathematical proof** that you *have* a valid signature, without revealing what the signature is.

This is called a zero-knowledge proof. Think of it like this:

> 🔑 You show a locksmith a sealed envelope and prove that it contains a key that opens a specific lock — without ever opening the envelope.

The proof is created by a system called **SP1** and compacted into a tiny 260-byte package called a **Groth16 proof**. This is what gets submitted to the blockchain.

### Layer 3 — On-Chain Verification 📜

The Stellar smart contract checks the proof mathematically. If the proof is valid, the XLM transfer happens. If anything is wrong — wrong destination, wrong amount, someone trying to replay an old transaction — the contract rejects it instantly.

**Your private key never touches the internet. Ever.**

---

## 4. Getting Started — Step by Step

### Step 1 · Install Nebula

Open your terminal (Command Prompt on Windows is not supported — use macOS or Linux) and run:

```bash
curl -fsSL https://raw.githubusercontent.com/Eshan276/nebulav2/main/install.sh | bash
```

This downloads the Nebula program to your computer. It works on:
- 🍎 macOS (Apple Silicon / Intel)
- 🐧 Linux (x86_64)

After installation, verify it worked:

```bash
nebula --help
```

You should see a list of available commands. If you get a "command not found" error, add this to your shell config file (`~/.bashrc` or `~/.zshrc`):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then restart your terminal.

---

### Step 2 · Create Your Wallet

```bash
nebula wallet create
```

This generates your **XMSS keypair** — your unique quantum-safe identity. A file called `key.json` will appear in your current folder.

> ⚠️ **This file is your wallet.** Guard it like a password.
> - Do NOT upload it to Dropbox, Google Drive, or any cloud service (unencrypted)
> - Do NOT share it with anyone
> - Make an offline backup (USB drive, printed on paper in a secure location)

---

### Step 3 · Fund Your Wallet

Before you can send XLM with Nebula, you need to move funds into it from a regular Stellar account.

```bash
nebula fund --amount 100
```

This deposits 100 XLM from your Stellar account into your Nebula wallet contract. Your XLM is now held by the smart contract and can only be unlocked by a valid proof from your XMSS key.

---

### Step 4 · Check Your Balance

```bash
nebula wallet info
```

This shows:
- 💰 Your XLM balance
- 🔢 Your current nonce (transaction counter)
- 🔑 How many signing keys you have left (out of 1,024)

---

## 5. Sending and Receiving XLM

### Sending XLM

```bash
nebula withdraw --to GDEST...ADDR --amount 10
```

Replace `GDEST...ADDR` with the recipient's Stellar address (starts with `G`).

**What happens behind the scenes:**

1. ⏱️ Your computer signs the transaction with your XMSS key (instant, local)
2. ☁️ A zero-knowledge proof is generated in the cloud (~30–60 seconds)
3. ✅ The proof is submitted to the Stellar blockchain
4. 📤 XLM arrives at the destination

The wait comes from step 2 — generating the cryptographic proof. This is normal.

### Receiving XLM

Your wallet address is your **pubkey hash** — a 32-byte identifier derived from your XMSS public key. Anyone can deposit XLM to your wallet by knowing this hash and calling the `deposit` function on the contract.

To see your wallet identity:

```bash
nebula wallet info
```

Your pubkey hash is displayed — share this with whoever wants to send you funds.

---

## 6. Using the Dashboard

```bash
nebula ui
```

This opens an interactive terminal dashboard:

```
╔══════════════════════════════════════╗
║         🌌 Nebula Wallet             ║
╠══════════════════════════════════════╣
║  Balance:     142.50 XLM             ║
║  Nonce:       3                      ║
║  Keys left:   1,021 / 1,024          ║
╠══════════════════════════════════════╣
║  [S] Send XLM                        ║
║  [R] Refresh                         ║
║  [Q] Quit                            ║
╚══════════════════════════════════════╝
```

Use keyboard shortcuts to navigate. Press `S` to open the send wizard, which guides you through the destination address and amount interactively.

---

## 7. Understanding Key Limits

Your Nebula wallet uses a technology where each transaction "uses up" one signing key. You start with **1,024 keys**.

| Keys used | Status |
|-----------|--------|
| 0 – 900 | 🟢 Plenty of keys left |
| 901 – 990 | 🟡 Consider creating a new wallet soon |
| 991 – 1,023 | 🔴 Create a new wallet and migrate your funds |
| 1,024 | 🚫 Wallet exhausted — cannot sign new transactions |

### What to do when keys run low

1. Create a new wallet: `nebula wallet create` (saves a new `key.json` in a different folder)
2. Fund the new wallet by sending XLM from the old wallet to the new one
3. Switch to using the new wallet's `key.json`

> The 1,024 key limit is a characteristic of the XMSS signature scheme. It's a deliberate trade-off: lower key count, higher quantum security.

---

## 8. Frequently Asked Questions

### ❓ Is Nebula safe to use with real money?

Nebula is currently deployed on **Stellar testnet** (not mainnet). Do not use it with real XLM that has monetary value. It is a research/demonstration project.

### ❓ What if I lose my key.json?

Your funds are locked in the smart contract and can only be accessed with your XMSS private key. If you lose `key.json`, **there is no recovery mechanism** — your XLM cannot be retrieved. Back it up carefully.

### ❓ What if a transaction fails?

If a transaction fails (network error, timeout, etc.), you'll lose one signing key but your balance is unaffected. Simply retry the transaction with:

```bash
nebula withdraw --to GDEST...ADDR --amount 10
```

The system is designed to handle this safely.

### ❓ How long does sending take?

- XMSS signing: < 1 second (local)
- ZK proof generation: ~30–60 seconds (cloud)
- Blockchain submission: ~5 seconds
- **Total: ~1–2 minutes**

### ❓ Can someone steal my XLM if they get my public key?

No. The XMSS public key is used to verify signatures but cannot be used to create them. Only your `key.json` (which contains the private key) can sign transactions.

### ❓ Does Nebula work on Windows?

Not currently. The CLI supports macOS and Linux. A browser extension with Windows support is in development.

### ❓ What is the Sindri cloud service?

Sindri is a zero-knowledge proof service that runs the cryptographic computation needed to generate a Groth16 proof. Your private key is **never** sent to Sindri — only the transaction data and proof inputs.

### ❓ What is a nonce?

A nonce (number used once) is a counter that prevents someone from replaying an old transaction. Each time you successfully send XLM, the nonce increments by 1. The proof is only valid for the current nonce value.

---

## 9. Safety Checklist

Before using Nebula, review this checklist:

- [ ] ✅ `key.json` is backed up offline (USB drive or printed)
- [ ] ✅ `key.json` is NOT in a cloud-synced folder
- [ ] ✅ `key.json` is NOT committed to any git repository
- [ ] ✅ You have noted how many keys remain (`nebula wallet info`)
- [ ] ✅ You have tested with a small amount before sending large transfers
- [ ] ✅ You have verified the destination address before sending

---

<div align="center">

**Ready to go deeper?** See the [Technical Reference](./TECHNICAL_REFERENCE.md) or [Architecture Guide](../ARCHITECTURE.md).

</div>
