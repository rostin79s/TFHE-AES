mod client;
use client::client_init;

mod server;
use server::aes_key_expansion;
use server::AES_encrypt;

fn main() {
    let (cks, sks, message_bits, key_bits) = client_init();






}

