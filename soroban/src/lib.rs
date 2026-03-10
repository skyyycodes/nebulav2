// Soroban contract: Falcon-512 ZK Verifier
//
// Wraps the Nethermind RISC Zero Groth16 verifier deployed on Stellar testnet:
//   CBY3GOBGQXDGRR4K2KYJO2UOXDW5NRW6UKIQHUBNBNU2V3BXQBXGTVX7
//
// Flow:
//   1. Caller provides: seal, image_id, journal (64 bytes), pubkey_hash, tx_hash
//   2. We verify journal == pubkey_hash || tx_hash
//   3. Cross-contract call to Nethermind verifier with (seal, image_id, sha256(journal))
//   4. If proof is valid, emit a Verified event and return true
//
// proof.json fields map to arguments:
//   seal        → seal       (Groth16 bytes with 4-byte selector prefix, from Boundless)
//   image_id    → image_id   (32 bytes)
//   journal     → journal    (64 bytes)
//   pubkey_hash → pubkey_hash (32 bytes)
//   tx_hash     → tx_hash    (32 bytes)

#![no_std]

use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype,
    Address, Bytes, BytesN, Env,
};

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    VerifierContract,
}

// ── Cross-contract client for Nethermind verifier ────────────────────────────

mod verifier_contract {
    use soroban_sdk::{contractclient, Bytes, BytesN, Env};

    #[contractclient(name = "VerifierClient")]
    pub trait Verifier {
        fn verify(
            env: Env,
            seal: Bytes,
            image_id: BytesN<32>,
            journal_digest: BytesN<32>,
        );
    }
}

use verifier_contract::VerifierClient;

// ── Events ────────────────────────────────────────────────────────────────────

#[contractevent]
pub struct FalconVerifiedEvent {
    pub pubkey_hash: BytesN<32>,
    pub tx_hash: BytesN<32>,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct FalconVerifier;

#[contractimpl]
impl FalconVerifier {
    /// Set the Nethermind verifier contract address (call once after deploy).
    /// Testnet address: CBY3GOBGQXDGRR4K2KYJO2UOXDW5NRW6UKIQHUBNBNU2V3BXQBXGTVX7
    pub fn set_verifier(env: Env, verifier: Address) {
        env.storage()
            .instance()
            .set(&DataKey::VerifierContract, &verifier);
    }

    /// Returns the configured verifier contract address.
    pub fn get_verifier(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::VerifierContract)
            .unwrap()
    }

    /// Verify a Falcon-512 ZK proof on-chain.
    ///
    /// Arguments (from proof.json):
    ///   seal        — Groth16 proof bytes from Boundless (proof.json "seal")
    ///                 Format: 4-byte selector || 256-byte Groth16 proof
    ///   image_id    — RISC Zero guest image ID, 32 bytes (proof.json "image_id")
    ///   journal     — Journal from zkVM: sha256(pubkey) || sha256(tx), 64 bytes
    ///   pubkey_hash — sha256(falcon_pubkey), 32 bytes (proof.json "pubkey_hash")
    ///   tx_hash     — sha256(stellar_xdr_tx), 32 bytes (proof.json "tx_hash")
    ///
    /// Returns true if proof is valid. Traps on any failure.
    pub fn verify_falcon_tx(
        env: Env,
        seal: Bytes,
        image_id: BytesN<32>,
        journal: Bytes,
        pubkey_hash: BytesN<32>,
        tx_hash: BytesN<32>,
    ) -> bool {
        // 1. Journal must be exactly 64 bytes
        assert!(journal.len() == 64, "journal must be 64 bytes");

        // 2. journal must equal pubkey_hash || tx_hash
        let mut expected = Bytes::new(&env);
        expected.append(&pubkey_hash.clone().into());
        expected.append(&tx_hash.clone().into());
        assert!(journal == expected, "journal mismatch");

        // 3. sha256(journal) is the public input the Nethermind verifier checks
        let journal_digest: BytesN<32> = env.crypto().sha256(&journal).into();

        // 4. Load verifier address
        let verifier_addr: Address = env
            .storage()
            .instance()
            .get(&DataKey::VerifierContract)
            .unwrap_or_else(|| panic!("call set_verifier first"));

        // 5. Cross-contract call — panics if proof is invalid
        let client = VerifierClient::new(&env, &verifier_addr);
        client.verify(&seal, &image_id, &journal_digest);

        // 6. Emit event
        FalconVerifiedEvent {
            pubkey_hash,
            tx_hash,
        }
        .publish(&env);

        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{Bytes, BytesN, Env};
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn test_journal_validation_passes() {
        let env = Env::default();

        let pk_bytes = [0xAAu8; 32];
        let tx_bytes = [0xBBu8; 32];

        let mut journal_raw = [0u8; 64];
        journal_raw[..32].copy_from_slice(&pk_bytes);
        journal_raw[32..].copy_from_slice(&tx_bytes);
        let journal = Bytes::from_array(&env, &journal_raw);

        let mut expected = Bytes::new(&env);
        expected.append(&Bytes::from_array(&env, &pk_bytes));
        expected.append(&Bytes::from_array(&env, &tx_bytes));

        assert_eq!(journal.len(), 64);
        assert_eq!(journal, expected);
    }

    #[test]
    #[should_panic]
    fn test_wrong_journal_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(FalconVerifier, ());
        let client = FalconVerifierClient::new(&env, &contract_id);

        client.set_verifier(&Address::generate(&env));

        let pubkey_hash = BytesN::<32>::from_array(&env, &[0xAAu8; 32]);
        let tx_hash = BytesN::<32>::from_array(&env, &[0xBBu8; 32]);
        let image_id = BytesN::<32>::from_array(&env, &[0x00u8; 32]);
        // Wrong journal (all zeros, not pubkey_hash || tx_hash)
        let bad_journal = Bytes::from_array(&env, &[0x00u8; 64]);

        client.verify_falcon_tx(
            &Bytes::new(&env),
            &image_id,
            &bad_journal,
            &pubkey_hash,
            &tx_hash,
        );
    }
}
