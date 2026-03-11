// XMSS-SHA2_10_256 Verification Circuit (RFC 8391 + xmss-0.1.0-pre.0 crate)
//
// Parameters: n=32, h=10, w=16, len=67 (len1=64, len2=3), padding_len=32
//
// Signature layout (2500 bytes total):
//   [0..4]       idx       (u32 big-endian, leaf index)
//   [4..36]      r         (randomness, 32 bytes)
//   [36..2180]   wots_sig  (67 x 32 bytes WOTS+ signature)
//   [2180..2500] auth      (10 x 32 bytes auth path)
//
// Public key layout (68 bytes):
//   [0..4]   OID      (4 bytes)
//   [4..36]  root     (32 bytes, Merkle tree root)
//   [36..68] pub_seed (32 bytes)
//
// ZK statement:
//   Private: public_key, tx_bytes, wots_sig, auth_path, r, sig_idx
//   Public:  pubkey_hash = sha256(public_key)
//            tx_hash     = sha256(tx_bytes)
//            nonce       = leaf_index

use sha256::digest as sha256_digest;

global TX_MAX: u32 = 512;

// --- ADRS helpers ---
// ADRS is [u32; 8] serialized as 32 big-endian bytes:
// [layer(4)][tree_hi(4)][tree_lo(4)][type(4)][ots/ltree/tree_idx(4)][chain/tree_height(4)][hash/tree_index(4)][key_and_mask(4)]
// Byte offsets:  0        4           8         12        16                  20                   24                 28

fn make_ots_adrs(ots_addr: u32) -> [u8; 32] {
    let mut adrs = [0 as u8; 32];
    // type = 0 (OTS), word[3] at bytes 12..16 -- leave as 0
    // ots_addr in word[4] at bytes 16..20
    adrs[16] = ((ots_addr >> 24) & 0xff) as u8;
    adrs[17] = ((ots_addr >> 16) & 0xff) as u8;
    adrs[18] = ((ots_addr >> 8) & 0xff) as u8;
    adrs[19] = (ots_addr & 0xff) as u8;
    adrs
}

fn make_ltree_adrs(leaf_idx: u32) -> [u8; 32] {
    let mut adrs = [0 as u8; 32];
    // type = 1 (L-tree), word[3] at bytes 12..16
    adrs[15] = 1;
    // leaf_idx in word[4] at bytes 16..20
    adrs[16] = ((leaf_idx >> 24) & 0xff) as u8;
    adrs[17] = ((leaf_idx >> 16) & 0xff) as u8;
    adrs[18] = ((leaf_idx >> 8) & 0xff) as u8;
    adrs[19] = (leaf_idx & 0xff) as u8;
    adrs
}

fn make_hashtree_adrs() -> [u8; 32] {
    let mut adrs = [0 as u8; 32];
    // type = 2 (hash tree), word[3] at bytes 12..16
    adrs[15] = 2;
    adrs
}

fn adrs_set_chain(adrs: [u8; 32], i: u32) -> [u8; 32] {
    // word[5] at bytes 20..24
    let mut a = adrs;
    a[20] = ((i >> 24) & 0xff) as u8;
    a[21] = ((i >> 16) & 0xff) as u8;
    a[22] = ((i >> 8) & 0xff) as u8;
    a[23] = (i & 0xff) as u8;
    a
}

fn adrs_set_hash(adrs: [u8; 32], j: u32) -> [u8; 32] {
    // word[6] at bytes 24..28
    let mut a = adrs;
    a[24] = ((j >> 24) & 0xff) as u8;
    a[25] = ((j >> 16) & 0xff) as u8;
    a[26] = ((j >> 8) & 0xff) as u8;
    a[27] = (j & 0xff) as u8;
    a
}

fn adrs_set_key_and_mask(adrs: [u8; 32], km: u32) -> [u8; 32] {
    // word[7] at bytes 28..32
    let mut a = adrs;
    a[28] = ((km >> 24) & 0xff) as u8;
    a[29] = ((km >> 16) & 0xff) as u8;
    a[30] = ((km >> 8) & 0xff) as u8;
    a[31] = (km & 0xff) as u8;
    a
}

fn adrs_set_tree_height(adrs: [u8; 32], h: u32) -> [u8; 32] {
    // word[5] at bytes 20..24
    let mut a = adrs;
    a[20] = ((h >> 24) & 0xff) as u8;
    a[21] = ((h >> 16) & 0xff) as u8;
    a[22] = ((h >> 8) & 0xff) as u8;
    a[23] = (h & 0xff) as u8;
    a
}

fn adrs_set_tree_index(adrs: [u8; 32], idx: u32) -> [u8; 32] {
    // word[6] at bytes 24..28
    let mut a = adrs;
    a[24] = ((idx >> 24) & 0xff) as u8;
    a[25] = ((idx >> 16) & 0xff) as u8;
    a[26] = ((idx >> 8) & 0xff) as u8;
    a[27] = (idx & 0xff) as u8;
    a
}

// --- SHA-256 based primitives matching xmss-0.1.0-pre.0 crate ---
// For XMSS-SHA2_10_256: n=32, padding_len=32

// PRF(key, adrs_bytes) = SHA256(toByte(3,32) || key[32] || adrs_bytes[32])
fn prf(key: [u8; 32], adrs: [u8; 32]) -> [u8; 32] {
    let mut msg = [0 as u8; 96];
    // padding: toByte(3, 32) -- 32 bytes, last byte = 3
    msg[31] = 3;
    for i in 0..32 { msg[32 + i] = key[i]; }
    for i in 0..32 { msg[64 + i] = adrs[i]; }
    sha256_digest(msg)
}

// thash_f(x) = SHA256(toByte(0,32) || PRF(pub_seed, adrs_km0) || (x XOR PRF(pub_seed, adrs_km1)))
fn thash_f(pub_seed: [u8; 32], adrs: [u8; 32], x: [u8; 32]) -> [u8; 32] {
    let adrs_km0 = adrs_set_key_and_mask(adrs, 0);
    let adrs_km1 = adrs_set_key_and_mask(adrs, 1);
    let key = prf(pub_seed, adrs_km0);
    let bitmask = prf(pub_seed, adrs_km1);
    let mut msg = [0 as u8; 96];
    // padding: toByte(0, 32) -- all zeros already
    for i in 0..32 { msg[32 + i] = key[i]; }
    for i in 0..32 { msg[64 + i] = x[i] ^ bitmask[i]; }
    sha256_digest(msg)
}

// thash_h(left, right) = SHA256(toByte(1,32) || PRF(pub_seed, adrs_km0) || (left XOR bm0) || (right XOR bm1))
fn thash_h(pub_seed: [u8; 32], adrs: [u8; 32], left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let adrs_km0 = adrs_set_key_and_mask(adrs, 0);
    let adrs_km1 = adrs_set_key_and_mask(adrs, 1);
    let adrs_km2 = adrs_set_key_and_mask(adrs, 2);
    let key = prf(pub_seed, adrs_km0);
    let bm0 = prf(pub_seed, adrs_km1);
    let bm1 = prf(pub_seed, adrs_km2);
    let mut msg = [0 as u8; 128];
    // padding: toByte(1, 32) -- last byte = 1
    msg[31] = 1;
    for i in 0..32 { msg[32 + i] = key[i]; }
    for i in 0..32 { msg[64 + i] = left[i] ^ bm0[i]; }
    for i in 0..32 { msg[96 + i] = right[i] ^ bm1[i]; }
    sha256_digest(msg)
}

// --- WOTS+ chain ---
// gen_chain: apply thash_f `steps` times starting from position `start`.
// set_hash_addr(addr, i) for each step i in start..start+steps
// Max steps = w-1 = 15.
fn wots_chain(x: [u8; 32], start: u32, steps: u32, pub_seed: [u8; 32], adrs: [u8; 32]) -> [u8; 32] {
    let mut tmp = x;
    for k in 0..15 {
        let active = (k as u32) < steps;
        let step = start + k as u32;
        // set_hash_addr(addr, step) -- word[6] at bytes 24..28
        let adrs_k = adrs_set_hash(adrs, step);
        let hashed = thash_f(pub_seed, adrs_k, tmp);
        let mut next = [0 as u8; 32];
        for b in 0..32 {
            next[b] = if active { hashed[b] } else { tmp[b] };
        }
        tmp = next;
    }
    tmp
}

// --- WOTS+ public key recovery from signature ---
fn wots_pk_from_sig(
    sig: [[u8; 32]; 67],
    msg: [u8; 32],
    pub_seed: [u8; 32],
    adrs: [u8; 32],
) -> [[u8; 32]; 67] {
    // base_w: split msg bytes into nibbles (w=16, log_w=4)
    let mut base_w: [u32; 67] = [0; 67];
    for i in 0..32 {
        base_w[2 * i]     = (msg[i] >> 4) as u32;
        base_w[2 * i + 1] = (msg[i] & 0x0f) as u32;
    }

    // checksum: len2=3, log_w=4, csum_shift = 8 - (3*4)%8 = 4
    // csum_bytes = 2 bytes big-endian; base_w extracts 3 nibbles
    let mut csum: u32 = 0;
    for i in 0..64 {
        csum = csum + (15 - base_w[i]);
    }
    csum = csum << 4;
    base_w[64] = (csum >> 12) & 0xf;
    base_w[65] = (csum >> 8) & 0xf;
    base_w[66] = (csum >> 4) & 0xf;

    let mut pk = [[0 as u8; 32]; 67];
    for i in 0..67 {
        // set_chain_addr(addr, i) -- word[5] at bytes 20..24
        let chain_adrs = adrs_set_chain(adrs, i as u32);
        let steps = 15 - base_w[i];
        pk[i] = wots_chain(sig[i], base_w[i], steps, pub_seed, chain_adrs);
    }
    pk
}

// --- L-tree compression ---
// Compress 67 WOTS+ pk nodes into a single leaf using thash_h.
// Level structure (from Rust l_tree, l starts at 67):
//   L0: l=67, 33 pairs, odd=1 (src=66, dst=33) -> l=34
//   L1: l=34, 17 pairs, odd=0                  -> l=17
//   L2: l=17,  8 pairs, odd=1 (src=16, dst=8)  -> l=9
//   L3:  l=9,  4 pairs, odd=1 (src=8, dst=4)   -> l=5
//   L4:  l=5,  2 pairs, odd=1 (src=4, dst=2)   -> l=3
//   L5:  l=3,  1 pair,  odd=1 (src=2, dst=1)   -> l=2
//   L6:  l=2,  1 pair,  odd=0                  -> l=1
fn ltree(wots_pk: [[u8; 32]; 67], pub_seed: [u8; 32], adrs: [u8; 32]) -> [u8; 32] {
    let mut nodes = [[0 as u8; 32]; 128];
    for i in 0..67 { nodes[i] = wots_pk[i]; }

    // (pairs, has_odd, odd_src, odd_dst) for each of 7 levels
    let pairs_arr:   [u32; 7] = [33, 17, 8, 4, 2, 1, 1];
    let has_odd_arr: [bool; 7] = [true, false, true, true, true, true, false];
    let odd_src_arr: [u32; 7] = [66, 0, 16, 8, 4, 2, 0];
    let odd_dst_arr: [u32; 7] = [33, 0, 8, 4, 2, 1, 0];

    for level in 0..7 {
        let pairs   = pairs_arr[level];
        let has_odd = has_odd_arr[level];
        let odd_src = odd_src_arr[level];
        let odd_dst = odd_dst_arr[level];

        // set_tree_height = level (word[5] at bytes 20..24)
        let h_adrs = adrs_set_tree_height(adrs, level as u32);

        // Hash all pairs using thash_h
        for j in 0..64 {
            let active = (j as u32) < pairs;
            // set_tree_index = j (word[6] at bytes 24..28)
            let idx_adrs = adrs_set_tree_index(h_adrs, j as u32);
            let hashed = thash_h(pub_seed, idx_adrs, nodes[2 * j], nodes[2 * j + 1]);
            for b in 0..32 {
                nodes[j][b] = if active { hashed[b] } else { nodes[j][b] };
            }
        }

        // Carry odd node if needed
        if has_odd {
            nodes[odd_dst] = nodes[odd_src];
        }
    }
    nodes[0]
}

// --- Auth path root computation ---
fn compute_root(
    leaf: [u8; 32],
    leaf_idx: u32,
    auth_path: [[u8; 32]; 10],
    pub_seed: [u8; 32],
    adrs: [u8; 32],
) -> [u8; 32] {
    let mut node = leaf;
    let mut idx = leaf_idx;
    for k in 0..10 {
        let h_adrs = adrs_set_tree_index(adrs_set_tree_height(adrs, k as u32), idx / 2);
        let sibling = auth_path[k];
        let is_left = (idx % 2) == 0;
        let new_node = if is_left {
            thash_h(pub_seed, h_adrs, node, sibling)
        } else {
            thash_h(pub_seed, h_adrs, sibling, node)
        };
        node = new_node;
        idx = idx / 2;
    }
    node
}

// --- H_msg: message hash ---
// hash_message: SHA256(toByte(2,32) || r[32] || root[32] || idx_as_n_bytes[32] || tx[TX_MAX])
// For n=32, padding_len=32: total = 32+32+32+32+TX_MAX = 128+512 = 640 bytes
fn h_msg(r: [u8; 32], root: [u8; 32], idx: u32, tx: [u8; TX_MAX]) -> [u8; 32] {
    let mut buf = [0 as u8; 640];
    // padding: toByte(2, 32) -- 32 bytes, last byte = 2
    buf[31] = 2;
    for i in 0..32 { buf[32 + i] = r[i]; }
    for i in 0..32 { buf[64 + i] = root[i]; }
    // idx as 32 bytes (last 4 bytes hold the u32)
    buf[124] = ((idx >> 24) & 0xff) as u8;
    buf[125] = ((idx >> 16) & 0xff) as u8;
    buf[126] = ((idx >> 8) & 0xff) as u8;
    buf[127] = (idx & 0xff) as u8;
    for i in 0..TX_MAX { buf[128 + i] = tx[i]; }
    sha256_digest(buf)
}

// --- Main circuit ---

fn main(
    // Private witness
    public_key: [u8; 68],
    tx_bytes:   [u8; TX_MAX],
    sig_idx:    u32,
    sig_r:      [u8; 32],
    wots_sig:   [[u8; 32]; 67],
    auth_path:  [[u8; 32]; 10],

    // Public inputs
    pubkey_hash: pub [u8; 32],
    tx_hash:     pub [u8; 32],
    nonce:       pub u32,
) {
    // 1. Verify pubkey_hash == sha256(public_key)
    let computed_pk_hash = sha256_digest(public_key);
    assert(computed_pk_hash == pubkey_hash, "pubkey_hash mismatch");

    // 2. Verify tx_hash == sha256(tx_bytes)
    let computed_tx_hash = sha256_digest(tx_bytes);
    assert(computed_tx_hash == tx_hash, "tx_hash mismatch");

    // 3. Verify nonce == sig_idx
    assert(sig_idx == nonce, "nonce mismatch");

    // 4. XMSS signature verification

    let mut root = [0 as u8; 32];
    let mut pub_seed = [0 as u8; 32];
    for i in 0..32 { root[i] = public_key[4 + i]; }
    for i in 0..32 { pub_seed[i] = public_key[36 + i]; }

    let msg_hash = h_msg(sig_r, root, sig_idx, tx_bytes);

    let ots_adrs = make_ots_adrs(sig_idx);
    let wots_pk = wots_pk_from_sig(wots_sig, msg_hash, pub_seed, ots_adrs);

    let ltree_adrs = make_ltree_adrs(sig_idx);
    let leaf = ltree(wots_pk, pub_seed, ltree_adrs);

    let ht_adrs = make_hashtree_adrs();
    let computed_root = compute_root(leaf, sig_idx, auth_path, pub_seed, ht_adrs);

    assert(computed_root == root, "XMSS signature verification failed");
}
