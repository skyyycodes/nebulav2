import json
import subprocess
import sys
from stellar_sdk import Keypair, Network, TransactionBuilder

# Falcon-512 (FN-DSA, FIPS 206) — keygen/sign done via Rust `keygen` binary
# This ensures the same falcon-rs format is used in both signing and zkVM verification.
KEYGEN_BIN = "prover/target/release/keygen"


def build_stellar_tx_bytes() -> bytes:
    """Build a minimal Stellar XDR transaction and return the raw XDR bytes."""
    from stellar_sdk import Account, Asset
    source = Keypair.random()
    destination = Keypair.random().public_key
    source_account = Account(account=source.public_key, sequence=1)

    builder = TransactionBuilder(
        source_account=source_account,
        network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
        base_fee=100,
    )
    builder.append_payment_op(destination=destination, asset=Asset.native(), amount="10")
    builder.set_timeout(30)
    tx = builder.build()

    return tx.to_xdr().encode()


def generate_and_sign(tx_bytes: bytes, output_path: str = "proof_inputs.json"):
    """Use Rust keygen binary to generate Falcon-512 keypair, sign tx_bytes, write proof_inputs.json."""
    tx_hex = tx_bytes.hex()
    result = subprocess.run(
        [KEYGEN_BIN, tx_hex, output_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"keygen binary failed: {result.returncode}")
    print(result.stdout, end="")
    with open(output_path) as f:
        return json.load(f)


if __name__ == "__main__":
    print("Algorithm: Falcon-512 (FN-DSA, FIPS 206)\n")

    tx_bytes = build_stellar_tx_bytes()
    print(f"Stellar XDR tx ({len(tx_bytes)} bytes): {tx_bytes[:48]}...\n")

    data = generate_and_sign(tx_bytes)
    print(f"\nproof_inputs.json written — ready for RISC Zero prover.")
