//! SP1 guest: XMSS-SHA2_10_256 verification (no xmss crate, pure sha2 only)
//!
//! Private inputs (sp1_zkvm::io::read):
//!   pk_bytes:  Vec<u8>  68 bytes  [OID(4) || root(32) || pub_seed(32)]
//!   tx_bytes:  Vec<u8>  arbitrary
//!   sig_bytes: Vec<u8>  2500 bytes [idx(4) || r(32) || wots(67x32) || auth(10x32)]
//!
//! Public outputs (sp1_zkvm::io::commit):
//!   pubkey_hash: [u8;32]   sha256(pk_bytes)
//!   tx_hash:     [u8;32]   sha256(tx_bytes)
//!   nonce:       u32       leaf index

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

// ---------- SHA-256 primitives (XMSS-SHA2_10_256: n=32, padding_len=32) ----------

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn prf(key: &[u8; 32], adrs: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[31] = 3; // toByte(PRF=3, 32)
    buf[32..64].copy_from_slice(key);
    buf[64..96].copy_from_slice(adrs);
    sha256(&buf)
}

fn addr_set_km(adrs: &[u8; 32], km: u32) -> [u8; 32] {
    let mut a = *adrs;
    a[28] = (km >> 24) as u8;
    a[29] = (km >> 16) as u8;
    a[30] = (km >> 8) as u8;
    a[31] = km as u8;
    a
}

fn thash_f(pub_seed: &[u8; 32], adrs: &[u8; 32], x: &[u8; 32]) -> [u8; 32] {
    let key = prf(pub_seed, &addr_set_km(adrs, 0));
    let bm  = prf(pub_seed, &addr_set_km(adrs, 1));
    let mut buf = [0u8; 96];
    // buf[0..32] = toByte(F=0, 32) = all zeros
    buf[32..64].copy_from_slice(&key);
    for i in 0..32 { buf[64 + i] = x[i] ^ bm[i]; }
    sha256(&buf)
}

fn thash_h(pub_seed: &[u8; 32], adrs: &[u8; 32], l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let key = prf(pub_seed, &addr_set_km(adrs, 0));
    let bm0 = prf(pub_seed, &addr_set_km(adrs, 1));
    let bm1 = prf(pub_seed, &addr_set_km(adrs, 2));
    let mut buf = [0u8; 128];
    buf[31] = 1; // toByte(H=1, 32)
    buf[32..64].copy_from_slice(&key);
    for i in 0..32 { buf[64 + i] = l[i] ^ bm0[i]; }
    for i in 0..32 { buf[96 + i] = r[i] ^ bm1[i]; }
    sha256(&buf)
}

fn h_msg(r: &[u8; 32], root: &[u8; 32], idx: u32, tx: &[u8]) -> [u8; 32] {
    let mut buf = vec![0u8; 128 + tx.len()];
    buf[31] = 2; // toByte(HASH=2, 32)
    buf[32..64].copy_from_slice(r);
    buf[64..96].copy_from_slice(root);
    let idx_bytes = (idx as u64).to_be_bytes();
    buf[120..128].copy_from_slice(&idx_bytes); // last 8 bytes of the 32-byte idx field [96..128]
    buf[128..].copy_from_slice(tx);
    sha256(&buf)
}

// ---------- ADRS helpers ----------

fn u32_to_be(v: u32) -> [u8; 4] { v.to_be_bytes() }

fn make_ots_adrs(ots_idx: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    // type=0 (OTS), word[4]=ots_idx at bytes 16..20
    a[16..20].copy_from_slice(&u32_to_be(ots_idx));
    a
}

fn make_ltree_adrs(leaf_idx: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[15] = 1; // type=1
    a[16..20].copy_from_slice(&u32_to_be(leaf_idx));
    a
}

fn make_hashtree_adrs() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[15] = 2; // type=2
    a
}

fn adrs_set_chain(a: &[u8; 32], i: u32) -> [u8; 32] {
    let mut b = *a; b[20..24].copy_from_slice(&u32_to_be(i)); b
}
fn adrs_set_hash(a: &[u8; 32], i: u32) -> [u8; 32] {
    let mut b = *a; b[24..28].copy_from_slice(&u32_to_be(i)); b
}
fn adrs_set_tree_height(a: &[u8; 32], h: u32) -> [u8; 32] {
    let mut b = *a; b[20..24].copy_from_slice(&u32_to_be(h)); b
}
fn adrs_set_tree_index(a: &[u8; 32], i: u32) -> [u8; 32] {
    let mut b = *a; b[24..28].copy_from_slice(&u32_to_be(i)); b
}

// ---------- WOTS+ ----------

fn wots_chain(x: &[u8; 32], start: u32, steps: u32, pub_seed: &[u8; 32], adrs: &[u8; 32]) -> [u8; 32] {
    let mut tmp = *x;
    for i in start..start + steps {
        let a = adrs_set_hash(adrs, i);
        tmp = thash_f(pub_seed, &a, &tmp);
    }
    tmp
}

fn wots_pk_from_sig(
    sig: &[[u8; 32]; 67],
    msg: &[u8; 32],
    pub_seed: &[u8; 32],
    ots_adrs: &[u8; 32],
) -> [[u8; 32]; 67] {
    // base_w: 64 nibbles from msg
    let mut lengths = [0u32; 67];
    for i in 0..32 {
        lengths[2 * i]     = (msg[i] >> 4) as u32;
        lengths[2 * i + 1] = (msg[i] & 0xf) as u32;
    }
    // checksum
    let csum: u32 = lengths[..64].iter().map(|&v| 15 - v).sum::<u32>() << 4;
    lengths[64] = (csum >> 12) & 0xf;
    lengths[65] = (csum >> 8)  & 0xf;
    lengths[66] = (csum >> 4)  & 0xf;

    let mut pk = [[0u8; 32]; 67];
    for i in 0..67 {
        let chain_adrs = adrs_set_chain(ots_adrs, i as u32);
        pk[i] = wots_chain(&sig[i], lengths[i], 15 - lengths[i], pub_seed, &chain_adrs);
    }
    pk
}

// ---------- L-tree ----------

fn ltree(wots_pk: &[[u8; 32]; 67], pub_seed: &[u8; 32], ltree_adrs: &[u8; 32]) -> [u8; 32] {
    let mut nodes: Vec<[u8; 32]> = wots_pk.to_vec();
    let mut l = 67usize;
    let mut height = 0u32;
    while l > 1 {
        let pairs = l >> 1;
        let adrs_h = adrs_set_tree_height(ltree_adrs, height);
        for i in 0..pairs {
            let a = adrs_set_tree_index(&adrs_h, i as u32);
            nodes[i] = thash_h(pub_seed, &a, &nodes[2 * i], &nodes[2 * i + 1]);
        }
        if l & 1 != 0 {
            nodes[l >> 1] = nodes[l - 1];
            l = (l >> 1) + 1;
        } else {
            l >>= 1;
        }
        height += 1;
    }
    nodes[0]
}

// ---------- Auth path root ----------

fn compute_root(
    leaf: &[u8; 32],
    leaf_idx: u32,
    auth: &[[u8; 32]; 10],
    pub_seed: &[u8; 32],
    ht_adrs: &[u8; 32],
) -> [u8; 32] {
    let mut node = *leaf;
    let mut idx = leaf_idx;
    for k in 0..10u32 {
        let a = adrs_set_tree_index(&adrs_set_tree_height(ht_adrs, k), idx / 2);
        node = if idx % 2 == 0 {
            thash_h(pub_seed, &a, &node, &auth[k as usize])
        } else {
            thash_h(pub_seed, &a, &auth[k as usize], &node)
        };
        idx >>= 1;
    }
    node
}

// ---------- Main ----------

pub fn main() {
    let pk_bytes:  Vec<u8> = sp1_zkvm::io::read();
    let tx_bytes:  Vec<u8> = sp1_zkvm::io::read();
    let sig_bytes: Vec<u8> = sp1_zkvm::io::read();

    assert_eq!(pk_bytes.len(),  68,   "pk must be 68 bytes");
    assert_eq!(sig_bytes.len(), 2500, "sig must be 2500 bytes");

    // Parse public key
    let root:     [u8; 32] = pk_bytes[4..36].try_into().unwrap();
    let pub_seed: [u8; 32] = pk_bytes[36..68].try_into().unwrap();

    // Parse signature
    let idx = u32::from_be_bytes(sig_bytes[0..4].try_into().unwrap());
    let r:   [u8; 32] = sig_bytes[4..36].try_into().unwrap();
    let mut wots_sig = [[0u8; 32]; 67];
    for i in 0..67 {
        wots_sig[i] = sig_bytes[36 + i * 32..36 + (i + 1) * 32].try_into().unwrap();
    }
    let mut auth = [[0u8; 32]; 10];
    for i in 0..10 {
        let off = 36 + 67 * 32 + i * 32;
        auth[i] = sig_bytes[off..off + 32].try_into().unwrap();
    }

    // Verify
    let msg_hash = h_msg(&r, &root, idx, &tx_bytes);
    let ots_adrs = make_ots_adrs(idx);
    let wots_pk  = wots_pk_from_sig(&wots_sig, &msg_hash, &pub_seed, &ots_adrs);
    let ltree_adrs = make_ltree_adrs(idx);
    let leaf = ltree(&wots_pk, &pub_seed, &ltree_adrs);
    let ht_adrs = make_hashtree_adrs();
    let computed_root = compute_root(&leaf, idx, &auth, &pub_seed, &ht_adrs);

    assert_eq!(computed_root, root, "XMSS signature verification failed");

    // Commit public outputs
    let pubkey_hash: [u8; 32] = sha256(&pk_bytes);
    let tx_hash:     [u8; 32] = sha256(&tx_bytes);
    sp1_zkvm::io::commit(&pubkey_hash);
    sp1_zkvm::io::commit(&tx_hash);
    sp1_zkvm::io::commit(&idx);
}
