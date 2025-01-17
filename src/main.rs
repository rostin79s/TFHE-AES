mod client;
mod server;
mod tables;

use client::client_init;
use server::AES_encrypt;

use tfhe::set_server_key;

fn main() {
    let (cks, sks, encrypted_round_keys, mut encrypted_message_bits ) = client_init();
    
    // rayon::broadcast(|_| set_server_key(sks.clone()));
    // set_server_key(sks);

    let start = std::time::Instant::now();

    AES_encrypt(&cks, &sks, &mut encrypted_message_bits, &encrypted_round_keys);

    // enumerate the encrypted message bits and decrypt %2 
    // and reconstruct the original 128 bit message
    let mut message = 0;
    let num_bits = encrypted_message_bits.len();
    for (i, bit) in encrypted_message_bits.iter().enumerate() {
        let decrypted_bit = cks.decrypt(bit) % 2;
        println!("x{}: {}", i, decrypted_bit);
        // Calculate the position from MSB
        let position = num_bits - 1 - i;
        message |= (decrypted_bit as u128) << position;
    }
    println!("Message: {:032x}", message);
    


    let elapsed = start.elapsed();
    println!("Time elapsed: {:?}", elapsed);





}

