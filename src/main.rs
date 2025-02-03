mod client;
mod server;
mod tables;

use client::Client;
use server::server::{aes_encrypt, aes_decrypt};



fn main() {
    
    let client = Client::new();

    let (cks, sks, wopbs_key, mut state, encrypted_round_keys) = client.client_encrypt();

    // let start = std::time::Instant::now();

    // aes_encrypt(&cks, &sks, &wopbs_key, &encrypted_round_keys, &mut state);

    // let elapsed = start.elapsed();
    // println!("Time taken for aes encryption: {:?}", elapsed);

    // let mut fhe_decrypted_state = state.clone();

    // let start = std::time::Instant::now();

    // aes_decrypt(&cks, &sks, &wopbs_key, &encrypted_round_keys, &mut fhe_decrypted_state);

    // let elapsed = start.elapsed();
    // println!("Time taken for aes decryption: {:?}", elapsed);

    // client.client_decrypt_and_verify(state, fhe_decrypted_state);

    // let mut message = 0;
    // let num_bytes = fhe_decrypted_state.len();

    // for (i, state_byte) in fhe_decrypted_state.iter().enumerate() {
    //     let decrypted_byte: u128 = cks.decrypt_without_padding(state_byte); // Decrypt as an 8-bit integer
    //     let position = (num_bytes - 1 - i) * 8; // Compute bit position from MSB
    //     message |= (decrypted_byte as u128) << position; // Store in the correct position
    // }

    // println!("Message: {:032x}", message);

}


