

use tfhe::shortint::Ciphertext;
use tfhe::integer::{wopbs::WopbsKey, ServerKey, RadixClientKey, ciphertext::BaseRadixCiphertext};
use rayon::prelude::*;

use crate::server::sbox;
use crate::server::encrypt::mix_columns;
use crate::server::encrypt::shift_rows;

use crate::server::decrypt::inv_mix_columns;
use crate::server::decrypt::inv_shift_rows;

pub fn aes_encrypt(cks: &RadixClientKey, sks: &ServerKey, wopbs_key: &WopbsKey, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>> , state: &mut Vec<BaseRadixCiphertext<Ciphertext>>){

    let rounds = 10;
    let state_size = 128; // AES works on 128-bit blocks
    let bytes_per_state = state_size / 8;

    let zero = cks.encrypt_without_padding(0 as u64);

    add_round_key(sks,  state, &encrypted_round_keys[0]);

    for round in 1..rounds {

        // let start = std::time::Instant::now();
        
        // for byte_ct in state.iter_mut() {
        //     sbox(cks, sks, wopbs_key, byte_ct);
        // }

        state.par_iter_mut().for_each(|byte_ct| {
            sbox(wopbs_key, byte_ct, false);
        });

        



        

        shift_rows(state);

  
        mix_columns(sks, state, &zero);

      
        add_round_key(sks, state, &encrypted_round_keys[round]);

        // println!("Total: {:?}", start.elapsed());
    }

    
    state.par_iter_mut().for_each(|byte_ct| {
        sbox(&wopbs_key, byte_ct, false);
    });
    shift_rows(state);
    add_round_key(sks, state, &encrypted_round_keys[rounds]);
}


pub fn aes_decrypt(cks: &RadixClientKey , sks: &ServerKey, wopbs_key: &WopbsKey, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>>, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    let rounds = 10; // Number of AES rounds

    // Initial round key addition
    add_round_key(sks, state, &encrypted_round_keys[rounds]);

    let zero = cks.encrypt_without_padding(0 as u64);


    for round in (1..rounds).rev() {
        // Inverse shift rows
        inv_shift_rows(state);

        // Inverse S-box
        state.par_iter_mut().for_each(|byte_ct| {
            sbox(wopbs_key, byte_ct, true);
        });

        // Add round key
        add_round_key(sks, state, &encrypted_round_keys[round]);

        // Inverse mix columns
        inv_mix_columns(sks, state, &zero);
    }

    // Final round (no inverse mix columns)
    inv_shift_rows(state);
    state.par_iter_mut().for_each(|byte_ct| {
        sbox(wopbs_key, byte_ct, true);
    });
    add_round_key(sks, state, &encrypted_round_keys[0]);
}


fn add_round_key(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, round_key: &Vec<BaseRadixCiphertext<Ciphertext>>) {
    for (state_byte, round_key_byte) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_byte, round_key_byte);
    }
}

