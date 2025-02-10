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

use rand::Rng;

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

// Main function to run the FHE AES CTR encryption. All functions, AES key expansion, encryption and decryption are run single threaded. Only CTR is parallelized.
fn main() {
    test();

    let args = Args::parse();


    let client_obj = Client::new(args.number_of_outputs, args.iv, args.key);

    let (public_key, server_key, wopbs_key, encrypted_iv, encrypted_key) = client_obj.client_encrypt();

    let server_obj = Server::new(public_key, server_key, wopbs_key);

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

// function to test the correctness of the AES key expansion, encryption and decryption in FHE with test vectors and random test cases.
// Takes a long time since all functions are single threaded, lower security paramters to see correctness faster.
fn test() {
    // Define the test vectors
    let test_vectors = vec![
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a"
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "30c81c46a35ce411e5fbc1191a0a52ef"
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "f69f2445df4f9b17ad2b417be66c3710"
        ),
    ];
    // Test the test vectors
    for (key_hex, plain_hex) in test_vectors {
        
        let client_obj = Client::new(1, u128::from_str_radix(&plain_hex, 16).unwrap(), u128::from_str_radix(key_hex, 16).unwrap());

        let (public_key, server_key, wopbs_key, mut state, encrypted_key) = client_obj.client_encrypt();

        let server_obj = Server::new(public_key, server_key, wopbs_key);

        

        // Perform AES key expansion
        let encrypted_round_keys = server_obj.aes_key_expansion(&encrypted_key);

        // FHE computation of AES encryption and decryption
        server_obj.aes_encrypt(&encrypted_round_keys, &mut state);
        let mut state_dec = state.clone();
        server_obj.aes_decrypt(&encrypted_round_keys, &mut state_dec);

        // Verify FHE computation
        client_obj.test_verify(&state, &state_dec);
    }

    // Test random test cases
    let mut rng = rand::thread_rng();
    for _ in 0..10 {
        let key = rng.gen::<u128>();
        let plain = rng.gen::<u128>();

        let client_obj = Client::new(1, plain, key);

        let (public_key, server_key, wopbs_key, mut state, encrypted_key) = client_obj.client_encrypt();

        let server_obj = Server::new(public_key, server_key, wopbs_key);

        // Perform AES key expansion
        let encrypted_round_keys = server_obj.aes_key_expansion(&encrypted_key);

        // FHE computation of AES encryption and decryption
        server_obj.aes_encrypt(&encrypted_round_keys, &mut state);
        let mut state_dec = state.clone();
        server_obj.aes_decrypt(&encrypted_round_keys, &mut state_dec);

        // verify FHE computation
        client_obj.test_verify(&state, &state_dec);
    }
}