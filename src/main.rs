mod client;
mod server;
mod tables;

use client::client::Client;
use server::server::Server;

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::shortint::Ciphertext;



fn main() {
    let client_obj = Client::new();

    let (cks, sks, wopbs_key, state, encrypted_key) = client_obj.client_encrypt();

    let server_obj = Server::new(cks, sks, wopbs_key);

    let encrypted_round_keys: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = server_obj.aes_key_expansion(&encrypted_key);


    loop {

    let mut copy_state = state.clone();

    let start = std::time::Instant::now();

    server_obj.aes_encrypt(&encrypted_round_keys, &mut copy_state);

    let elapsed = start.elapsed();
    println!("Time taken for aes encryption: {:?}", elapsed);

    let mut fhe_decrypted_state = copy_state.clone();

    let start = std::time::Instant::now();

    server_obj.aes_decrypt(&encrypted_round_keys, &mut fhe_decrypted_state);

    let elapsed = start.elapsed();
    println!("Time taken for aes decryption: {:?}", elapsed);

    let b = client_obj.client_decrypt_and_verify(copy_state, fhe_decrypted_state);

    if !b {
        break;
    }

    }

}
