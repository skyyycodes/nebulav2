//! Generate correct SP1Stdin JSON from proof_inputs.json
use sp1_sdk::SP1Stdin;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let inputs_path = args.get(1).map(|s| s.as_str()).unwrap_or("proof_inputs.json");

    let raw = std::fs::read_to_string(inputs_path).expect("cannot read proof_inputs.json");
    let d: serde_json::Value = serde_json::from_str(&raw).unwrap();

    let pk  = hex::decode(d["public_key"].as_str().unwrap()).unwrap();
    let tx  = hex::decode(d["tx_bytes"].as_str().unwrap()).unwrap();
    let sig = hex::decode(d["signature"].as_str().unwrap()).unwrap();

    let mut stdin = SP1Stdin::new();
    stdin.write::<Vec<u8>>(&pk);
    stdin.write::<Vec<u8>>(&tx);
    stdin.write::<Vec<u8>>(&sig);

    let json = serde_json::to_string(&stdin).unwrap();
    println!("{json}");
}
