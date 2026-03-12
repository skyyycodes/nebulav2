"""
bridge.py — orchestrates the SP1 XMSS ZK proof pipeline:

  1. XMSS sign tx → proof_inputs.json
  2. Submit proof to Sindri (SP1 Groth16)
  3. Poll until ready
  4. Parse proof → build stellar contract invoke command

Usage:
    python bridge.py [--skip-sign] [--skip-prove] [--proof-id <id>]

Env vars:
    SINDRI_API_KEY        — required for proving
    VERIFIER_CONTRACT_ID  — deployed Soroban XMSS verifier contract ID
    STELLAR_SECRET_KEY    — for contract invocation
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# Auto-load .env
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

ROOT = Path(__file__).parent
PROOF_INPUTS = ROOT / "proof_inputs.json"
PROOF_CACHE  = ROOT / "groth16_proof.json"

SINDRI_API = "https://sindri.app/api/v1"
GROTH16_CIRCUIT_ID = "45580910-1595-4c24-a03a-c7f54574e9b0"


# ── helpers ──────────────────────────────────────────────────────────────────

def sindri_request(path, data=None, method=None):
    api_key = os.environ.get("SINDRI_API_KEY", "")
    if not api_key:
        sys.exit("SINDRI_API_KEY not set")
    url = SINDRI_API + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method or ("POST" if body else "GET"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        sys.exit(f"Sindri HTTP {e.code}: {body[:300]}")


def bincode_vec_u8(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data


def build_sp1_stdin(pk: bytes, tx: bytes, sig: bytes) -> dict:
    """Build the SP1Stdin JSON that Sindri expects."""
    buffer = [
        list(bincode_vec_u8(pk)),
        list(bincode_vec_u8(tx)),
        list(bincode_vec_u8(sig)),
    ]
    return {"buffer": buffer, "ptr": 0, "proofs": []}


def decode_msgpack_proof(raw: bytes) -> dict:
    """Minimal msgpack decoder for SP1 Groth16 proof structure."""
    pos = [0]

    def rb():
        b = raw[pos[0]]; pos[0] += 1; return b

    def rbs(n):
        b = raw[pos[0]:pos[0]+n]; pos[0] += n; return b

    def decode():
        b = rb()
        if 0x90 <= b <= 0x9f: return [decode() for _ in range(b & 0x0f)]
        if 0x80 <= b <= 0x8f:
            d = {}
            for _ in range(b & 0x0f): k = decode(); v = decode(); d[k] = v
            return d
        if 0xa0 <= b <= 0xbf: return rbs(b & 0x1f).decode()
        if b == 0xd9: return rbs(rb()).decode()
        if b == 0xda: return rbs(struct.unpack(">H", rbs(2))[0]).decode()
        if b == 0xdb: return rbs(struct.unpack(">I", rbs(4))[0]).decode()
        if b == 0xc4: return rbs(rb())
        if b == 0xc5: return rbs(struct.unpack(">H", rbs(2))[0])
        if b == 0xc6: return rbs(struct.unpack(">I", rbs(4))[0])
        if b == 0xdc: return [decode() for _ in range(struct.unpack(">H", rbs(2))[0])]
        if b == 0xdd: return [decode() for _ in range(struct.unpack(">I", rbs(4))[0])]
        if b <= 0x7f: return b
        if b >= 0xe0: return b - 256
        if b == 0xcc: return rb()
        if b == 0xcd: return struct.unpack(">H", rbs(2))[0]
        if b == 0xce: return struct.unpack(">I", rbs(4))[0]
        if b == 0xcf: return struct.unpack(">Q", rbs(8))[0]
        raise ValueError(f"Unknown msgpack byte 0x{b:02x} at {pos[0]-1}")

    result = decode()
    inner = result[0]
    g16 = inner["Groth16"]
    pub_inputs, enc_proof_hex, raw_proof_hex, vkey_hash = g16
    if isinstance(vkey_hash, list):
        vkey_hash = bytes(vkey_hash)
    return {
        "pub_inputs": [str(pub_inputs[0]), str(pub_inputs[1])],
        "enc_proof": bytes.fromhex(enc_proof_hex),   # 256 bytes
        "raw_proof": bytes.fromhex(raw_proof_hex),   # 324 bytes
        "vkey_hash": vkey_hash,                       # 32 bytes
    }


def build_proof_bytes(enc_proof: bytes, vkey_hash: bytes) -> bytes:
    """Prepend 4-byte selector to get 260-byte SP1 Groth16 proof."""
    selector = vkey_hash[:4]
    return selector + enc_proof


def build_public_values(proof_inputs: dict) -> bytes:
    """Build 68-byte public_values: pubkey_hash(32) + tx_hash(32) + nonce(4 LE u32)."""
    pk = bytes.fromhex(proof_inputs["public_key"])
    tx = bytes.fromhex(proof_inputs["tx_bytes"])
    leaf_index = proof_inputs.get("leaf_index", 0)
    pubkey_hash = hashlib.sha256(pk).digest()
    tx_hash = hashlib.sha256(tx).digest()
    nonce = struct.pack("<I", leaf_index)
    return pubkey_hash + tx_hash + nonce


# ── steps ─────────────────────────────────────────────────────────────────────

def step_sign():
    """XMSS sign the tx → proof_inputs.json via xmss CLI."""
    xmss_bin = ROOT / "xmss" / "target" / "release" / "xmss"
    key_file  = ROOT / "key.json"

    if not xmss_bin.exists():
        print("Building XMSS binary...")
        import subprocess
        r = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=ROOT / "xmss",
        )
        if r.returncode != 0:
            sys.exit("xmss build failed")

    if not key_file.exists():
        print("Generating XMSS keypair...")
        import subprocess
        subprocess.run(
            [str(xmss_bin), "keygen", "--out", str(key_file)],
            check=True,
        )

    print("Signing tx with XMSS...")
    import subprocess
    tx_hex = "deadbeef" + "00" * 508  # 512-byte dummy tx
    subprocess.run(
        [str(xmss_bin), "sign", "--key", str(key_file), "--tx", tx_hex, "--out", str(PROOF_INPUTS)],
        check=True,
    )
    print(f"proof_inputs.json written ({PROOF_INPUTS.stat().st_size} bytes)")


def step_prove() -> str:
    """Submit proof job to Sindri, return proof_id."""
    inputs = json.loads(PROOF_INPUTS.read_text())
    pk  = bytes.fromhex(inputs["public_key"])
    tx  = bytes.fromhex(inputs["tx_bytes"])
    sig = bytes.fromhex(inputs["signature"])

    stdin = build_sp1_stdin(pk, tx, sig)
    print(f"Submitting to Sindri circuit {GROTH16_CIRCUIT_ID[:8]}...")
    resp = sindri_request(
        f"/circuit/{GROTH16_CIRCUIT_ID}/prove",
        {"proof_input": json.dumps(stdin)},
    )
    proof_id = resp["proof_id"]
    print(f"Proof job submitted: {proof_id[:8]}...")
    return proof_id


def step_poll(proof_id: str) -> dict:
    """Poll Sindri until proof is ready, return detail response."""
    print(f"Polling proof {proof_id[:8]}...", end="", flush=True)
    for i in range(120):
        detail = sindri_request(f"/proof/{proof_id}/detail")
        status = detail.get("status", "?")
        if status == "Ready":
            print(f" Ready ({detail.get('compute_time', '')})")
            return detail
        if status in ("Failed", "Timed Out"):
            err = detail.get("error", "")
            sys.exit(f"\nProof {status}: {err[:300]}")
        print(".", end="", flush=True)
        time.sleep(30)
    sys.exit("\nTimed out waiting for proof")


def step_parse_and_print(detail: dict, inputs: dict):
    """Parse the Groth16 proof and print the stellar contract invoke command."""
    proof_b64 = detail["proof"]["proof"]
    raw = base64.b64decode(proof_b64)
    parsed = decode_msgpack_proof(raw)

    enc_proof  = parsed["enc_proof"]   # 256 bytes
    vkey_hash  = parsed["vkey_hash"]   # 32 bytes
    pub_inputs = parsed["pub_inputs"]  # [str, str]

    proof_bytes     = build_proof_bytes(enc_proof, vkey_hash)
    public_values   = build_public_values(inputs)

    # program_vkey = pub_inputs[0] as 32-byte BE
    program_vkey_int = int(pub_inputs[0])
    program_vkey = program_vkey_int.to_bytes(32, "big")

    # Save to cache
    cache = {
        "proof_id":       detail["proof_id"],
        "proof_bytes":    proof_bytes.hex(),
        "public_values":  public_values.hex(),
        "program_vkey":   program_vkey.hex(),
        "vkey_hash":      vkey_hash.hex(),
        "pubkey_hash":    public_values[:32].hex(),
        "tx_hash":        public_values[32:64].hex(),
        "nonce":          struct.unpack("<I", public_values[64:])[0],
    }
    PROOF_CACHE.write_text(json.dumps(cache, indent=2))
    print(f"Proof cached to {PROOF_CACHE}")

    contract_id = os.environ.get("VERIFIER_CONTRACT_ID", "<deploy first>")
    secret_key  = os.environ.get("STELLAR_SECRET_KEY", "YOUR_SECRET_KEY")
    not_deployed = contract_id.startswith("<")

    print(f"""
{'='*70}
PROOF READY
{'='*70}
proof_bytes   : {len(proof_bytes)} bytes
public_values : {len(public_values)} bytes
program_vkey  : {program_vkey.hex()}
vkey_hash     : {vkey_hash.hex()}
pubkey_hash   : {public_values[:32].hex()}
tx_hash       : {public_values[32:64].hex()}
nonce         : {cache['nonce']}
""")

    wasm = ROOT / "soroban" / "target" / "wasm32v1-none" / "release" / "sphincs_verifier.wasm"

    if not_deployed:
        print(f"""── Deploy ──────────────────────────────────────────────────────────────────
# Build the contract:
cd {ROOT}/soroban && cargo build --target wasm32v1-none --release

# Deploy:
stellar contract deploy \\
  --wasm {wasm} \\
  --source-account {secret_key} \\
  --network testnet

# Initialize with program_vkey:
stellar contract invoke \\
  --id <CONTRACT_ID> \\
  --source-account {secret_key} \\
  --network testnet \\
  -- init \\
  --program_vkey {program_vkey.hex()}

# Set VERIFIER_CONTRACT_ID=<CONTRACT_ID> in .env, then re-run bridge.py --skip-prove
""")
    else:
        print(f"""── Verify on Stellar testnet ────────────────────────────────────────────────
stellar contract invoke \\
  --id {contract_id} \\
  --source-account {secret_key} \\
  --network testnet \\
  -- verify_xmss_tx \\
  --proof_bytes {proof_bytes.hex()} \\
  --public_values {public_values.hex()}
""")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-sign",  action="store_true", help="Skip signing, use existing proof_inputs.json")
    parser.add_argument("--skip-prove", action="store_true", help="Skip proving, use cached groth16_proof.json")
    parser.add_argument("--proof-id",   help="Use an existing Sindri proof ID")
    args = parser.parse_args()

    if not args.skip_sign and not args.skip_prove and not args.proof_id:
        step_sign()
    else:
        if not PROOF_INPUTS.exists():
            sys.exit("proof_inputs.json not found — run without --skip-sign first")
        print(f"Using existing proof_inputs.json (leaf_index={json.loads(PROOF_INPUTS.read_text()).get('leaf_index',0)})")

    inputs = json.loads(PROOF_INPUTS.read_text())

    if args.skip_prove:
        if not PROOF_CACHE.exists():
            sys.exit("groth16_proof.json not found — run without --skip-prove first")
        cache = json.loads(PROOF_CACHE.read_text())
        print(f"Using cached proof {cache['proof_id'][:8]}...")
        proof_bytes   = bytes.fromhex(cache["proof_bytes"])
        public_values = bytes.fromhex(cache["public_values"])
        program_vkey  = bytes.fromhex(cache["program_vkey"])
        contract_id   = os.environ.get("VERIFIER_CONTRACT_ID", "<deploy first>")
        secret_key    = os.environ.get("STELLAR_SECRET_KEY", "YOUR_SECRET_KEY")
        wasm = ROOT / "soroban" / "target" / "wasm32v1-none" / "release" / "sphincs_verifier.wasm"
        print(f"""
stellar contract invoke \\
  --id {contract_id} \\
  --source-account {secret_key} \\
  --network testnet \\
  -- verify_xmss_tx \\
  --proof_bytes {proof_bytes.hex()} \\
  --public_values {public_values.hex()}
""")
        return

    proof_id = args.proof_id or step_prove()
    detail   = step_poll(proof_id)
    step_parse_and_print(detail, inputs)
    print("Done.")


if __name__ == "__main__":
    main()
