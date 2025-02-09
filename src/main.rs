mod client;
mod server;
mod tables;

use client::client::Client;
use server::server::Server;

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::shortint::Ciphertext;

// To parse command-line arguments
use clap::Parser;

// To parallelize AES CTR
use rayon::prelude::*;

/// Struct to define command-line arguments
#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_parser)]
    number_of_outputs: usize,

    #[arg(long, value_parser)]
    iv: u128,

    #[arg(long, value_parser)]
    key: u128,
}

fn main() {
    let args = Args::parse();


    let client_obj = Client::new(args.number_of_outputs, args.iv, args.key);

    let (client_key, public_key, server_key, wopbs_key, encrypted_iv, encrypted_key) = client_obj.client_encrypt();

    let server_obj = Server::new(client_key, public_key, server_key, wopbs_key);

    // AES key expansion
    let start = std::time::Instant::now();
    let encrypted_round_keys: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = server_obj.aes_key_expansion(&encrypted_key);
    let key_expansion_elapsed = start.elapsed();
    println!("AES key expansion took: {:?}", key_expansion_elapsed);

    // parallel AES CTR
    let start_ctr = std::time::Instant::now();
    let mut vec_fhe_encrypted_states: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = (0..args.number_of_outputs)
    .into_par_iter()
    .map(|i| {

        let mut state = encrypted_iv.clone();
        server_obj.add_scalar(&mut state, i as u128);
        server_obj.aes_encrypt(&encrypted_round_keys, &mut state);
        state
    })
    .collect();

    let ctr_elapsed = start_ctr.elapsed();
    println!("AES of #{:?} outputs computed in: {ctr_elapsed:?}", args.number_of_outputs);

    // Client decrypts FHE computations and verifies correctness using aes crate.
    client_obj.client_decrypt_and_verify(&mut vec_fhe_encrypted_states);

}
