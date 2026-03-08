import json
import oqs
from stellar_sdk import Keypair, Network, TransactionBuilder, Server

# SLH-DSA (SPHINCS+) — NIST FIPS 205
# Using SHAKE variant: better pure-Rust RISC-V compat in the zkVM guest
ALGORITHM = "SLH_DSA_PURE_SHAKE_128F"


def generate_keypair():
    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
    return public_key, private_key


def build_stellar_tx_bytes() -> bytes:
    """Build a minimal Stellar XDR transaction and return the raw XDR bytes."""
    # Use a throwaway source keypair (Ed25519) just to build a valid XDR envelope.
    # The SPHINCS+ key is separate — it signs the XDR bytes, not the Stellar tx itself.
    source = Keypair.random()
    destination = Keypair.random().public_key

    builder = TransactionBuilder(
        source_account=source.public_key,
        network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
        base_fee=100,
    )
    builder.append_payment_op(destination=destination, asset_code="XLM", amount="10")
    builder.set_timeout(30)
    tx = builder.build()

    # Return raw XDR bytes of the transaction envelope
    return tx.to_xdr().encode()


def sign_tx_bytes(tx_bytes: bytes, private_key: bytes) -> bytes:
    with oqs.Signature(ALGORITHM, secret_key=private_key) as signer:
        return signer.sign(tx_bytes)


def verify_tx_bytes(tx_bytes: bytes, signature: bytes, public_key: bytes) -> bool:
    with oqs.Signature(ALGORITHM) as verifier:
        return verifier.verify(tx_bytes, signature, public_key)


def export_proof_inputs(public_key: bytes, tx_bytes: bytes, signature: bytes, path="proof_inputs.json"):
    """Write inputs for the RISC Zero host to consume."""
    data = {
        "public_key": public_key.hex(),
        "tx_bytes": tx_bytes.hex(),
        "signature": signature.hex(),
        "algorithm": ALGORITHM,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Exported proof inputs → {path}")


if __name__ == "__main__":
    print(f"Algorithm: {ALGORITHM}\n")

    # 1. Generate SPHINCS+ keypair
    pub, priv = generate_keypair()
    print(f"Public key  ({len(pub)} bytes): {pub.hex()[:48]}...")
    print(f"Private key ({len(priv)} bytes): {priv.hex()[:48]}...\n")

    # 2. Build a Stellar XDR transaction
    tx_bytes = build_stellar_tx_bytes()
    print(f"Stellar XDR tx ({len(tx_bytes)} bytes): {tx_bytes[:48]}...\n")

    # 3. Sign with SPHINCS+ private key
    sig = sign_tx_bytes(tx_bytes, priv)
    print(f"Signature ({len(sig)} bytes): {sig.hex()[:48]}...\n")

    # 4. Verify locally
    valid = verify_tx_bytes(tx_bytes, sig, pub)
    print(f"Local verification: {'PASS' if valid else 'FAIL'}")

    # 5. Tamper test
    tampered = tx_bytes[:-1] + bytes([tx_bytes[-1] ^ 0xFF])
    print(f"Tampered tx:       {'PASS' if verify_tx_bytes(tampered, sig, pub) else 'FAIL (expected)'}\n")

    # 6. Export for ZK prover
    export_proof_inputs(pub, tx_bytes, sig)
