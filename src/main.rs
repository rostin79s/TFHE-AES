mod client;
mod server;
mod tables;

use client::Client;
use server::AES_encrypt;

use tfhe::{
    integer::{
        gen_keys_radix, wopbs::*,
    },
    shortint::parameters::WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
};

use tfhe::integer::*;
use tfhe::shortint::*;

// use tfhe::shortint::prelude::*;
// use tfhe::shortint::parameters::DynamicDistribution;


fn gen_lut<F, T>(message_mod: usize, carry_mod: usize, poly_size: usize, ct: &T, f: F) -> IntegerWopbsLUT 
    where
        F: Fn(u64) -> u64,
        T: IntegerCiphertext,
    {
        let log_message_modulus =
            f64::log2((message_mod) as f64) as u64;
        let log_carry_modulus = f64::log2((carry_mod) as f64) as u64;
        let log_basis = log_message_modulus + log_carry_modulus;
        let delta = 64 - log_basis;
        let nb_block = ct.blocks().len();
        let poly_size = poly_size;
        let mut lut_size = 1 << (nb_block * log_basis as usize);
        if lut_size < poly_size {
            lut_size = poly_size;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(nb_block));

        for index in 0..lut_size {
            // find the value represented by the index
            let mut value = 0;
            let mut tmp_index = index;
            for i in 0..nb_block as u64 {
                let tmp = tmp_index % (1 << log_basis); // Extract only the relevant block
                tmp_index >>= log_basis; // Move to the next block
                value += tmp << (log_message_modulus * i); // Properly reconstruct `value`
            }

            // fill the LUTs
            for block_index in 0..nb_block {
                let masked_value = (f(value as u64) >> (log_message_modulus * block_index as u64))
                    % (1 << log_message_modulus);  // Mask the value using the message modulus
            
                lut[block_index][index] = masked_value << delta;  // Apply delta to the LUT entry
            }
        }
        lut
    }


fn main() {
    
    let client = Client::new();

    let (cks, sks, wopbs_key, mut state, encrypted_round_keys) = client.client_encrypt();

    let start = std::time::Instant::now();

    AES_encrypt(&cks, &sks, &wopbs_key, &encrypted_round_keys, &mut state);

    let elapsed = start.elapsed();
    println!("Time taken: {:?}", elapsed);

    client.client_decrypt_and_verify(&state);


    // let mut message = 0;
    // let num_bytes = state.len();

    // for (i, state_byte) in state.iter().enumerate() {
    //     let decrypted_byte: u128 = cks.decrypt_without_padding(state_byte); // Decrypt as an 8-bit integer
    //     let position = (num_bytes - 1 - i) * 8; // Compute bit position from MSB
    //     message |= (decrypted_byte as u128) << position; // Store in the correct position
    // }
    
    // println!("Message: {:032x}", message);
}


fn test(){
    let nb_block = 8;
    let (cks, sks) = gen_keys_radix(WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, nb_block);

    let (cks_s, sks_s) = gen_keys(WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS);



    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

    let message_mod = cks.parameters().message_modulus().0;
    let carry_mod = cks.parameters().carry_modulus().0;



    println!("Modulus: {}", message_mod);
    println!("Carry: {}", carry_mod);

    let mut moduli = 1_u64;
    for _ in 0..nb_block {
        moduli *= cks.parameters().message_modulus().0 as u64;
    }
    println!("Moduli: {}", moduli);

    let x = 2;
    let y = x>>0;
    println!("y: {}", y);

    let clear = 1 % moduli;
    let mut ct = cks.encrypt_without_padding(clear as u64);

    


    let mut blocks: &mut [tfhe::shortint::Ciphertext] = ct.blocks_mut();
    let scal_s = cks_s.encrypt_without_padding(1 as u64);

    let mut scal = cks.encrypt_without_padding(1 as u64);
    let mut blocks_s = scal.blocks_mut();
    
    sks_s.unchecked_add_assign(&mut blocks[0], &blocks_s[0]);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);

    let poly_size = 512;
    let f = |x| x as u64;
    
    let lut = gen_lut(message_mod, carry_mod, poly_size, &ct, f);

    let scal = cks.encrypt_without_padding(1 as u64);

    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);

    let start = std::time::Instant::now();

    let ct_res = wopbs_key.wopbs_without_padding(&ct, &lut);

    let elapsed = start.elapsed();
    println!("Time taken: {:?}", elapsed);



    let res: u64 = cks.decrypt_without_padding(&ct_res);
    println!("Result: {}", res);

    // assert_eq!(res, (clear * 2) % moduli)
}