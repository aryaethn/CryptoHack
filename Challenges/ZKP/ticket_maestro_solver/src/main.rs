use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

fn main() {
    let host = "archive.cryptohack.org:26896";
    let stream = TcpStream::connect(host).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    println!("hello: {}", line.trim());

    // buy one real ticket
    writer.write_all(b"\"BuyTicket\"\n").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();
    let proof_hex = resp["Ticket"]["proof"].as_str().unwrap().to_string();
    println!("got ticket proof: {}", proof_hex);

    let bytes = hex::decode(&proof_hex).unwrap();
    let proof = Proof::<Bn254>::deserialize(&bytes[..]).unwrap();

    let mut rng = thread_rng();

    // balance = 10 - COST_OF_TICKET(2) = 8
    let mut balance: i64 = 8;

    // Groth16 proof malleability: for any nonzero scalar t,
    // (t*A, t^-1*B, C) verifies against the exact same public input as (A,B,C),
    // since e(tA, t^-1 B) = e(A,B). Each rerandomized proof serializes to
    // different bytes, so the ticket-id (blake2b(digest||proof_bytes)) is fresh
    // every time, bypassing the "spent" set entirely.
    while balance < 20 {
        let t = Fr::rand(&mut rng);
        let t_inv = t.inverse().unwrap();

        let a2 = proof.a.mul(t.into_repr()).into_affine();
        let b2 = proof.b.mul(t_inv.into_repr()).into_affine();

        let new_proof = Proof::<Bn254> {
            a: a2,
            b: b2,
            c: proof.c,
        };

        let mut ser = vec![];
        new_proof.serialize(&mut ser).unwrap();
        let hex_proof = hex::encode(ser);

        let req = json!({"Redeem": {"proof": hex_proof}});
        writer.write_all(req.to_string().as_bytes()).unwrap();
        writer.write_all(b"\n").unwrap();

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let resp: Value = serde_json::from_str(&line).unwrap();
        if resp == json!("GoodTicket") {
            balance += 1;
            println!("redeemed, balance={}", balance);
        } else {
            println!("unexpected response: {:?}", resp);
            break;
        }
    }

    writer.write_all(b"\"BuyFlag\"\n").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    println!("flag response: {}", line.trim());
}
