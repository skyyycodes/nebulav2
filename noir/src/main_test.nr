use dep::sha256::{digest as sha256, sha256_var};

fn main(data: [u8; 32]) -> pub [u8; 32] {
    sha256(data)
}
