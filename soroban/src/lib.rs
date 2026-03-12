// Soroban contract: SP1 XMSS ZK Verifier
//
// Verifies SP1 Groth16 proofs (v4.0.0-rc.3 circuit) for XMSS-SHA2_10_256 signature verification.
//
// The SP1 guest (xmss-sp1-program) commits:
//   [0..32]  pubkey_hash  = sha256(xmss_pubkey)
//   [32..64] tx_hash      = sha256(tx_bytes)
//   [64..68] nonce        = bincode(u32 leaf_index)  [LE u32]
//   Total: 68 bytes (public_values)
//
// SP1 Groth16 proof format (proof_bytes, 260 bytes):
//   [0..4]   selector = first 4 bytes of VERIFIER_HASH (circuit-version check)
//   [4..68]  A: G1 point (X||Y, each 32 bytes BE)
//   [68..196] B: G2 point (X.c1||X.c0||Y.c1||Y.c0, each 32 bytes BE)
//             Note: SP1 encoded_proof already uses (c1||c0) Soroban order — no swap needed.
//   [196..260] C: G1 point (X||Y, each 32 bytes BE)
//
// Groth16 verification equation:
//   e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
//
//   Which is checked as:
//   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
//   pairing_check([-A, alpha, vk_x, C], [B, beta, gamma, delta]) == true
//
//   vk_x = IC[0] + inputs[0]*IC[1] + inputs[1]*IC[2]
//   inputs[0] = uint256(programVKey)
//   inputs[1] = sha256(publicValues) & ((1<<253) - 1)
//
// VK from sp1-contracts/v4.0.0-rc.3/Groth16Verifier.sol (circuit v4.0.0-rc.3)

#![no_std]

use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype,
    Bytes, BytesN, Env, Vec,
};
use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr};

// ── VK constants (SP1 v4.0.0-rc.3) ──────────────────────────────────────────
//
// All uint256 values encoded as 32-byte big-endian arrays.
// G1 = X(32B) || Y(32B), G2 = X_c1(32B) || X_c0(32B) || Y_c1(32B) || Y_c0(32B)
// (Soroban G2 Fp2 format: imaginary part first)
// The "NEG" suffix in the Groth16Verifier.sol means these are -beta, -gamma, -delta.
// For the pairing check we use: pairing_check([-A, alpha, vk_x, C], [B, beta, gamma, delta])
// where beta = -BETA_NEG, gamma = -GAMMA_NEG, delta = -DELTA_NEG in G2.
// BUT since pairing_check already takes separate G1/G2 pairs, we can use:
// pairing_check([-A, alpha, vk_x, C], [B, -BETA_NEG, -GAMMA_NEG, -DELTA_NEG])
// i.e., negate the G2 Y-coordinate to un-negate.

// Helper: uint256 decimal → 32-byte big-endian
// We store these as const byte arrays.

// ALPHA_G1 (positive alpha)
// X = 20491192805390485299153009773594534940189261866228447918068658471970481763042
// Y = 9383485363053290200918347156157836566562967994039712273449902621266178545958
const ALPHA_G1_BYTES: [u8; 64] = [
    // X (big-endian)
    0x2d, 0x4d, 0x9a, 0xa7, 0xe3, 0x02, 0xd9, 0xdf,
    0x41, 0x74, 0x9d, 0x55, 0x07, 0x94, 0x9d, 0x05,
    0xdb, 0xea, 0x33, 0xfb, 0xb1, 0x6c, 0x64, 0x3b,
    0x22, 0xf5, 0x99, 0xa2, 0xbe, 0x6d, 0xf2, 0xe2,
    // Y (big-endian)
    0x14, 0xbe, 0xdd, 0x50, 0x3c, 0x37, 0xce, 0xb0,
    0x61, 0xd8, 0xec, 0x60, 0x20, 0x9f, 0xe3, 0x45,
    0xce, 0x89, 0x83, 0x0a, 0x19, 0x23, 0x03, 0x01,
    0xf0, 0x76, 0xca, 0xff, 0x00, 0x4d, 0x19, 0x26,
];

// BETA_NEG_G2 (negated beta in G2)
// In Groth16Verifier.sol: BETA_NEG_X_0, BETA_NEG_X_1, BETA_NEG_Y_0, BETA_NEG_Y_1
// X_0 = 6375614351688725206403948262868962793625744043794305715222011528459656738731
// X_1 = 4252822878758300859123897981450591353533073413197771768651442665752259397132
// Y_0 = 11383000245469012944693504663162918391286475477077232690815866754273895001727
// Y_1 = 41207766310529818958173054109690360505148424997958324311878202295167071904
// Note: Solidity uses (X_1||X_0) for Fp2 X, (Y_1||Y_0) for Fp2 Y
// Soroban G2: c1||c0 per coordinate → X: X_1||X_0, Y: Y_1||Y_0 (same convention)
const BETA_NEG_G2_BYTES: [u8; 128] = [
    // X_c1 = X_1 (big-endian)
    0x09, 0x67, 0x03, 0x2f, 0xcb, 0xf7, 0x76, 0xd1,
    0xaf, 0xc9, 0x85, 0xf8, 0x88, 0x77, 0xf1, 0x82,
    0xd3, 0x84, 0x80, 0xa6, 0x53, 0xf2, 0xde, 0xca,
    0xa9, 0x79, 0x4c, 0xbc, 0x3b, 0xf3, 0x06, 0x0c,
    // X_c0 = X_0 (big-endian)
    0x0e, 0x18, 0x78, 0x47, 0xad, 0x4c, 0x79, 0x83,
    0x74, 0xd0, 0xd6, 0x73, 0x2b, 0xf5, 0x01, 0x84,
    0x7d, 0xd6, 0x8b, 0xc0, 0xe0, 0x71, 0x24, 0x1e,
    0x02, 0x13, 0xbc, 0x7f, 0xc1, 0x3d, 0xb7, 0xab,
    // Y_c1 = Y_1 (big-endian)
    0x00, 0x17, 0x52, 0xa1, 0x00, 0xa7, 0x2f, 0xdf,
    0x1e, 0x5a, 0x5d, 0x6e, 0xa8, 0x41, 0xcc, 0x20,
    0xec, 0x83, 0x8b, 0xcc, 0xfc, 0xf7, 0xbd, 0x55,
    0x9e, 0x79, 0xf1, 0xc9, 0xc7, 0x59, 0xb6, 0xa0,
    // Y_c0 = Y_0 (big-endian)
    0x19, 0x2a, 0x8c, 0xc1, 0x3c, 0xd9, 0xf7, 0x62,
    0x87, 0x1f, 0x21, 0xe4, 0x34, 0x51, 0xc6, 0xca,
    0x9e, 0xea, 0xb2, 0xcb, 0x29, 0x87, 0xc4, 0xe3,
    0x66, 0xa1, 0x85, 0xc2, 0x5d, 0xac, 0x2e, 0x7f,
];

// GAMMA_NEG_G2 (negated gamma in G2)
// X_0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781
// X_1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634
// Y_0 = 13392588948715843804641432497768002650278120570034223513918757245338268106653
// Y_1 = 17805874995975841540914202342111839520379459829704422454583296818431106115052
const GAMMA_NEG_G2_BYTES: [u8; 128] = [
    // X_c1 = X_1
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a,
    0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12,
    0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    // X_c0 = X_0
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76,
    0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd,
    0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    // Y_c1 = Y_1
    0x27, 0x5d, 0xc4, 0xa2, 0x88, 0xd1, 0xaf, 0xb3,
    0xcb, 0xb1, 0xac, 0x09, 0x18, 0x75, 0x24, 0xc7,
    0xdb, 0x36, 0x39, 0x5d, 0xf7, 0xbe, 0x3b, 0x99,
    0xe6, 0x73, 0xb1, 0x3a, 0x07, 0x5a, 0x65, 0xec,
    // Y_c0 = Y_0
    0x1d, 0x9b, 0xef, 0xcd, 0x05, 0xa5, 0x32, 0x3e,
    0x6d, 0xa4, 0xd4, 0x35, 0xf3, 0xb6, 0x17, 0xcd,
    0xb3, 0xaf, 0x83, 0x28, 0x5c, 0x2d, 0xf7, 0x11,
    0xef, 0x39, 0xc0, 0x15, 0x71, 0x82, 0x7f, 0x9d,
];

// DELTA_NEG_G2 (negated delta in G2)
// X_0 = 19629295988673812457237747993086053613709181874324227239033635205670891327060
// X_1 = 17270349666695681994109533429817368669497520119106681015856196115021033411091
// Y_0 = 14281790459332470419125837541415772351574094165485379719795056490664770278727
// Y_1 = 12217031863885588059779845498016696484811402332435719653934590968575679828494
const DELTA_NEG_G2_BYTES: [u8; 128] = [
    // X_c1 = X_1
    0x26, 0x2e, 0xab, 0xe8, 0x15, 0x11, 0xaa, 0x8e,
    0x30, 0x34, 0xcb, 0xd7, 0x5d, 0x42, 0xe7, 0x08,
    0xaa, 0x4e, 0xd8, 0x03, 0x03, 0xfb, 0x0e, 0x4f,
    0xb9, 0x0c, 0xd0, 0xff, 0x6e, 0x90, 0x92, 0x13,
    // X_c0 = X_0
    0x2b, 0x65, 0xc9, 0xae, 0x26, 0x05, 0xf3, 0xef,
    0x55, 0x40, 0xd3, 0xa6, 0x45, 0x03, 0xc8, 0x4f,
    0xe5, 0xe1, 0xd9, 0xec, 0x6e, 0xb1, 0xbd, 0x3a,
    0x90, 0x6b, 0xbc, 0x80, 0x83, 0x0e, 0x8e, 0x54,
    // Y_c1 = Y_1
    0x1b, 0x02, 0x98, 0x51, 0x53, 0xa1, 0xb7, 0x79,
    0xa4, 0x56, 0xc3, 0xc6, 0x5b, 0xee, 0x53, 0xbd,
    0x53, 0xef, 0xcc, 0xee, 0xc1, 0x0a, 0x7f, 0x53,
    0xbe, 0x8f, 0xaa, 0x0b, 0xd6, 0xc8, 0x92, 0x0e,
    // Y_c0 = Y_0
    0x1f, 0x93, 0x34, 0xfa, 0x25, 0x56, 0x61, 0x9b,
    0x13, 0x0c, 0x61, 0xd8, 0x3e, 0xd5, 0x5c, 0x12,
    0xe4, 0x50, 0xf8, 0xf5, 0xc5, 0x42, 0xa1, 0x39,
    0xc9, 0x72, 0x6c, 0xd3, 0x10, 0xae, 0x15, 0x47,
];

// IC[0] (CONSTANT)
// X = 6712036353136249806951869451908368653566549662781372756321174254690599374583
// Y = 18149145036868871064182651529802275370638950642742152190925800889169295968585
const IC0_BYTES: [u8; 64] = [
    // X
    0x0e, 0xd6, 0xe0, 0xc1, 0x3f, 0x35, 0x32, 0x62,
    0xae, 0x2d, 0xbb, 0xe4, 0x9c, 0xe6, 0xa0, 0xb6,
    0x75, 0x76, 0xd3, 0x8a, 0xaf, 0x59, 0x58, 0x56,
    0x4b, 0xe7, 0x64, 0x83, 0x56, 0x83, 0x0e, 0xf7,
    // Y
    0x28, 0x20, 0x0d, 0x54, 0x01, 0x35, 0x65, 0xdc,
    0xa1, 0x96, 0x84, 0x1d, 0x0a, 0x3c, 0xd7, 0xa5,
    0xf6, 0x75, 0x31, 0xf9, 0x74, 0x87, 0x72, 0xf5,
    0x53, 0xe1, 0xe9, 0x84, 0x5f, 0x6c, 0x09, 0x49,
];

// IC[1] (PUB_0 - for programVKey)
// X = 12384021290558951773126140100379496012525836638155233096890881157449062205923
// Y = 16530732960917040406371332977337573092100509754908292717547628595948196259098
const IC1_BYTES: [u8; 64] = [
    // X
    0x1b, 0x61, 0x1b, 0x8f, 0x69, 0x6f, 0x28, 0xff,
    0xb6, 0x25, 0x0c, 0x7f, 0xfa, 0xc6, 0x6e, 0xfb,
    0xd6, 0x38, 0xd9, 0x7f, 0x0d, 0x6c, 0x84, 0x3c,
    0x23, 0x69, 0x1c, 0x3a, 0xf5, 0x32, 0xc9, 0xe3,
    // Y
    0x24, 0x8c, 0x10, 0x33, 0xbd, 0x73, 0xc4, 0xff,
    0x82, 0x0d, 0x48, 0x0a, 0x37, 0xb3, 0x9c, 0xa6,
    0xef, 0x17, 0x85, 0x43, 0xc5, 0xc9, 0x19, 0x04,
    0x59, 0xe8, 0xcf, 0xe3, 0x6c, 0x48, 0xe5, 0x1a,
];

// IC[2] (PUB_1 - for committed_values_digest)
// X = 18749839173537272836199384751191600551090725238737491530604969678014545165197
// Y = 1828450848853234449784725988911172793808451038026258152543319358376349553777
const IC2_BYTES: [u8; 64] = [
    // X
    0x29, 0x74, 0x08, 0x6b, 0xde, 0x6c, 0x91, 0x26,
    0x7b, 0x20, 0x11, 0x37, 0xcf, 0xe6, 0xee, 0x8c,
    0xd5, 0x0f, 0xf0, 0xa3, 0xda, 0x86, 0x1e, 0x80,
    0x85, 0x03, 0xe7, 0xdf, 0x4d, 0xa8, 0x7b, 0x8d,
    // Y
    0x04, 0x0a, 0xdd, 0xd3, 0x59, 0x13, 0xf1, 0x1e,
    0xa6, 0x84, 0x6f, 0x0d, 0x58, 0x31, 0x26, 0xba,
    0xb9, 0xe8, 0xf8, 0xae, 0x69, 0x79, 0x7d, 0x4c,
    0x2c, 0x7f, 0x19, 0x5b, 0xe0, 0x78, 0x54, 0x71,
];

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    ProgramVKey,
}

// ── Events ────────────────────────────────────────────────────────────────────

#[contractevent]
pub struct XmssVerifiedEvent {
    pub pubkey_hash: BytesN<32>,
    pub tx_hash: BytesN<32>,
    pub nonce: u32,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct XmssVerifier;

#[contractimpl]
impl XmssVerifier {
    /// Initialize with the SP1 program vkey (sha256(groth16_vk.bin) from the XMSS program).
    /// Call once after deploy.
    pub fn init(env: Env, program_vkey: BytesN<32>) {
        env.storage()
            .instance()
            .set(&DataKey::ProgramVKey, &program_vkey);
    }

    /// Returns the configured program vkey.
    pub fn get_program_vkey(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::ProgramVKey)
            .unwrap()
    }

    /// Verify an XMSS ZK proof on-chain.
    ///
    /// proof_bytes:   260 bytes — 4-byte selector + 256-byte Groth16 proof
    /// public_values: 68 bytes  — pubkey_hash(32) + tx_hash(32) + nonce(4, bincode LE u32)
    ///
    /// Returns (pubkey_hash, tx_hash, nonce) on success. Panics on invalid proof.
    pub fn verify_xmss_tx(
        env: Env,
        proof_bytes: Bytes,
        public_values: Bytes,
    ) -> (BytesN<32>, BytesN<32>, u32) {
        let program_vkey: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::ProgramVKey)
            .unwrap_or_else(|| panic!("call init first"));

        // Verify the Groth16 proof
        Self::groth16_verify(&env, &proof_bytes, &public_values, &program_vkey);

        // Parse public values
        assert!(public_values.len() == 68, "public_values must be 68 bytes");

        let pubkey_hash: BytesN<32> = public_values
            .slice(0..32)
            .try_into()
            .unwrap_or_else(|_| panic!("pubkey_hash slice"));
        let tx_hash: BytesN<32> = public_values
            .slice(32..64)
            .try_into()
            .unwrap_or_else(|_| panic!("tx_hash slice"));

        // Nonce: bincode u32 = 4-byte LE
        let mut nb = [0u8; 4];
        let ns = public_values.slice(64..68);
        for i in 0..4u32 {
            nb[i as usize] = ns.get(i).unwrap();
        }
        let nonce = u32::from_le_bytes(nb);

        XmssVerifiedEvent {
            pubkey_hash: pubkey_hash.clone(),
            tx_hash: tx_hash.clone(),
            nonce,
        }
        .publish(&env);

        (pubkey_hash, tx_hash, nonce)
    }

    /// Core Groth16 verification using Soroban BN254 host functions.
    /// Uses SP1 v4.0.0-rc.3 hardcoded VK.
    fn groth16_verify(
        env: &Env,
        proof_bytes: &Bytes,
        public_values: &Bytes,
        program_vkey: &BytesN<32>,
    ) {
        assert!(proof_bytes.len() == 260, "proof must be 260 bytes (4 selector + 256 G16)");

        // Parse A, B, C from proof_bytes[4..]
        // A: G1 [4..68]
        let a_raw: BytesN<64> = proof_bytes.slice(4..68).try_into()
            .unwrap_or_else(|_| panic!("A parse"));
        let a = Bn254G1Affine::from_bytes(a_raw);

        // B: G2 [68..196]
        // SP1 encoded_proof stores B as (X.c1||X.c0||Y.c1||Y.c0) — already Soroban format
        let b_raw: BytesN<128> = proof_bytes.slice(68..196).try_into()
            .unwrap_or_else(|_| panic!("B parse"));
        let b = Bn254G2Affine::from_bytes(b_raw);

        // C: G1 [196..260]
        let c_raw: BytesN<64> = proof_bytes.slice(196..260).try_into()
            .unwrap_or_else(|_| panic!("C parse"));
        let c = Bn254G1Affine::from_bytes(c_raw);

        // Compute public inputs
        // inputs[0] = uint256(programVKey)
        let input0 = Fr::from_bytes(program_vkey.clone());

        // inputs[1] = sha256(publicValues) & ((1<<253) - 1)
        let pv_hash = env.crypto().sha256(public_values);
        let mut pv_arr = pv_hash.to_array();
        pv_arr[0] &= 0x1f; // mask top 3 bits → 253-bit value
        let input1 = Fr::from_bytes(BytesN::<32>::from_array(env, &pv_arr));

        // Load VK points
        let alpha_g1 = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &ALPHA_G1_BYTES));
        let beta_g2_neg = Bn254G2Affine::from_bytes(BytesN::<128>::from_array(env, &BETA_NEG_G2_BYTES));
        let gamma_g2_neg = Bn254G2Affine::from_bytes(BytesN::<128>::from_array(env, &GAMMA_NEG_G2_BYTES));
        let delta_g2_neg = Bn254G2Affine::from_bytes(BytesN::<128>::from_array(env, &DELTA_NEG_G2_BYTES));

        let ic0 = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &IC0_BYTES));
        let ic1 = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &IC1_BYTES));
        let ic2 = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &IC2_BYTES));

        // Compute vk_x = IC[0] + input0 * IC[1] + input1 * IC[2]
        let bn254 = env.crypto().bn254();
        let t1 = bn254.g1_mul(&ic1, &input0);
        let t2 = bn254.g1_mul(&ic2, &input1);
        let vk_x = ic0 + t1 + t2;

        // Negate A for the pairing check:
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1
        // But VK has -beta, -gamma, -delta, so:
        // e(-A, B) * e(alpha, -(-beta)) * e(vk_x, -(-gamma)) * e(C, -(-delta)) = 1
        // → e(-A, B) * e(alpha, -(beta_neg)) * e(vk_x, -(gamma_neg)) * e(C, -(delta_neg)) = 1
        //
        // In Soroban, we negate G2 by negating the Y coordinate (c1||c0 Y → c1||(p-c0))
        // But it's simpler to negate G1 instead:
        // The check is symmetric: e(A, -B) = e(-A, B)
        // So: e(A, -B) * e(alpha, beta) * ... = 1
        // where beta = -beta_neg means we need to negate beta_neg's G2.
        //
        // Alternative: use the pairing in the form that the VK provides:
        // The Groth16Verifier.sol does:
        //   pairing_check([-A, alpha, vk_x, C], [B, beta_neg, gamma_neg, delta_neg])
        // Wait, that's wrong. Let me re-read the Solidity verifier.
        //
        // Actually in Groth16Verifier.sol the VK has BETA_NEG, GAMMA_NEG, DELTA_NEG.
        // The verification equation becomes:
        //   e(A, B) * e(alpha, -beta_neg)^-1 * e(vk_x, -gamma_neg)^-1 * e(C, -delta_neg)^-1 = 1
        // Which is: e(-A, B) * e(alpha, -beta_neg) * e(vk_x, -gamma_neg) * e(C, -delta_neg) = 1
        // = e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1  (since neg of neg = original)
        //
        // Soroban pairing_check(g1_vec, g2_vec) checks product of e(g1[i], g2[i]) == 1.
        // So: [-A, alpha, vk_x, C] paired with [B, beta_neg_negated, gamma_neg_negated, delta_neg_negated]
        // = pairing_check([-A, alpha, vk_x, C], [B, beta, gamma, delta])
        //
        // Since VK provides -beta etc., and we want +beta, we negate the G2 Y coords of beta_neg.
        // OR equivalently, we negate A (G1) and keep beta_neg as-is:
        // pairing_check([-A, alpha, vk_x, C], [B, -beta_neg, -gamma_neg, -delta_neg])
        // But the VK stores -beta (= beta_neg), so -(-beta) = beta.
        //
        // In practice, the most common form used by Solidity/gnark is:
        // e(-A, B) + e(alpha, beta_neg) + e(vk_x, gamma_neg) + e(C, delta_neg) = 0 (additive)
        // where beta_neg = -beta (the negated beta).
        //
        // Let me just use the direct form matching the Solidity verifier:
        // The Solidity verifier passes BETA_NEG, GAMMA_NEG, DELTA_NEG to the precompile.
        // The precompile expects pairs that multiply to 1.
        // So: e(-A, B) * e(alpha, BETA_NEG) * e(vk_x, GAMMA_NEG) * e(C, DELTA_NEG) should = 1
        // This is because BETA_NEG = -beta in G2, and the equation is:
        // e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
        // → e(A, B) * e(alpha, -beta) * e(vk_x, -gamma) * e(C, -delta) = 1
        // → e(A, B) * e(alpha, BETA_NEG) * e(vk_x, GAMMA_NEG) * e(C, DELTA_NEG) = 1
        // (since alpha, vk_x, C are in G1, negating the G2 pairing partner inverts the pairing)
        // So we keep A positive (not negated) and use BETA_NEG, GAMMA_NEG, DELTA_NEG as-is!

        let mut g1_vec: Vec<Bn254G1Affine> = Vec::new(env);
        g1_vec.push_back(a);
        g1_vec.push_back(alpha_g1);
        g1_vec.push_back(vk_x);
        g1_vec.push_back(c);

        let mut g2_vec: Vec<Bn254G2Affine> = Vec::new(env);
        g2_vec.push_back(b);
        g2_vec.push_back(beta_g2_neg);
        g2_vec.push_back(gamma_g2_neg);
        g2_vec.push_back(delta_g2_neg);

        let result = bn254.pairing_check(g1_vec, g2_vec);
        assert!(result, "Groth16 proof verification failed");
    }

}
