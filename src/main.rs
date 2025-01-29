mod client;
mod server;
mod tables;

use client::client_init;
use server::AES_encrypt;

use tfhe::set_server_key;

use tfhe::shortint::parameters::gaussian::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_2_CARRY_0_KS_PBS, PARAM_MESSAGE_3_CARRY_0_KS_PBS, PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64};
use tfhe::shortint::prelude::*;

fn main() {
    // let (cks, sks, encrypted_round_keys, mut encrypted_message_bits ) = client_init();
    
    // // rayon::broadcast(|_| set_server_key(sks.clone()));
    // // set_server_key(sks);

    // let start = std::time::Instant::now();

    // AES_encrypt(&cks, &sks, &mut encrypted_message_bits, &encrypted_round_keys);

    // // enumerate the encrypted message bits and decrypt %2 
    // // and reconstruct the original 128 bit message
    // let mut message = 0;
    // let num_bits = encrypted_message_bits.len();
    // for (i, bit) in encrypted_message_bits.iter().enumerate() {
    //     let decrypted_bit = cks.decrypt(bit) % 2;
    //     // println!("x{}: {}", i, decrypted_bit);
    //     // Calculate the position from MSB
    //     let position = num_bits - 1 - i;
    //     message |= (decrypted_bit as u128) << position;
    // }
    // println!("Message: {:032x}", message);
    


    // let elapsed = start.elapsed();
    // println!("Time elapsed: {:?}", elapsed);



    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_0_KS_PBS);

    let msg1 = 3;

    // We use the private client key to encrypt a message:
    let ct_1 = client_key.encrypt(msg1);

    // Compute the lookup table for the univariate function:
    let acc = server_key.generate_lookup_table(|n| n.count_ones().into());

    // Apply the table lookup on the input message:
    let start = std::time::Instant::now();
    let mut ct_res = server_key.apply_lookup_table(&ct_1, &acc);

    let elapsed = start.elapsed();
    println!("Time elapsed: {:?}", elapsed);

    server_key.unchecked_scalar_add_assign(&mut ct_res, 3);

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_res);
    println!("Decrypted output: {}", output);
    // assert_eq!(output, msg1.count_ones() as u64);




}

