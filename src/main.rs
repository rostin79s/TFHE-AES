mod client;
mod server;
mod tables;

use client::client::Client;
use server::server::Server;

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::shortint::Ciphertext;

use clap::Parser;

/// Struct to define command-line arguments
#[derive(Parser, Debug)]
#[command(name = "FHE AES", about = "A Fully Homomorphic Encryption-based AES system.")]
struct Args {
    /// Number of outputs
    #[arg(long, value_parser)]
    number_of_outputs: usize,

    /// Initialization Vector (IV) - Should be a 16-byte hex string
    #[arg(long, value_parser)]
    iv: u128,

    /// AES Key - Should be a 16/24/32-byte hex string (AES-128, AES-192, AES-256)
    #[arg(long, value_parser)]
    key: u128,
}

fn main() {
    let args = Args::parse();

    println!("Number of Outputs: {}", args.number_of_outputs);
    println!("IV: {}", args.iv);
    println!("Key: {}", args.key);

    // Convert IV and Key from hex strings to byte arrays
    let number_of_outputs = args.number_of_outputs;
    let iv = args.iv;
    let key = args.key;


    let client_obj = Client::new(number_of_outputs, iv, key);

    let (client_key, public_key, server_key, wopbs_key, encrypted_iv, encrypted_key) = client_obj.client_encrypt();

    let server_obj = Server::new(client_key, public_key, server_key, wopbs_key);

    let start = std::time::Instant::now();

    let encrypted_round_keys: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = server_obj.aes_key_expansion(&encrypted_key);

    let elapsed = start.elapsed();
    println!("Time taken for key expansion: {:?}", elapsed);




    // loop number of outputs
    for i in 0..number_of_outputs{

        let start = std::time::Instant::now();

        // add encrypted_iv + i, where vector is storeing MSB to LSB,
        // dont use iv, use encrypted_iv and plus i it
        
        let mut state = encrypted_iv.clone();

        server_obj.aes_encrypt(&encrypted_round_keys, &mut state, i as u128);

        let elapsed = start.elapsed();
        println!("Time taken for aes encryption: {:?}", elapsed);

        // let mut fhe_decrypted_state = state.clone();

        // let start = std::time::Instant::now();

        // server_obj.aes_decrypt(&encrypted_round_keys, &mut fhe_decrypted_state);

        // let elapsed = start.elapsed();
        // println!("Time taken for aes decryption: {:?}", elapsed);

        client_obj.client_decrypt_and_verify(i, &mut state);
    }

}
