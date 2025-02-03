

use tfhe::shortint::Ciphertext;
use tfhe::integer::{wopbs::WopbsKey, ServerKey, RadixClientKey, ciphertext::BaseRadixCiphertext};
use rayon::prelude::*;

use crate::server::sbox;
use crate::server::encrypt::mix_columns;
use crate::server::encrypt::shift_rows;

use crate::server::decrypt::inv_mix_columns;
use crate::server::decrypt::inv_shift_rows;

use rayon::ThreadPoolBuilder;
use core_affinity::CoreId;

pub fn aes_encrypt(cks: &RadixClientKey, sks: &ServerKey, wopbs_key: &WopbsKey, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>> , state: &mut Vec<BaseRadixCiphertext<Ciphertext>>){

    let rounds = 10;

    let zero = cks.encrypt_without_padding(0 as u64); //  THIS NEEDS TO BE FIXED ???????????????????????????????????????????????????????????

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


pub fn aes_decrypt(cks: &RadixClientKey, sks: &ServerKey, wopbs_key: &WopbsKey, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>>, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    let rounds = 10; // Number of AES rounds

    // Initial round key addition
    add_round_key(sks, state, &encrypted_round_keys[rounds]);
    debug_state(state, rounds, cks, "add round key");

    let zero = cks.encrypt_without_padding(0 as u64);

    for round in (2..=rounds).rev() {
        inv_shift_rows(state);
        debug_state(state, round, cks, "inv shift rows");

        state.par_iter_mut().for_each(|byte_ct| {
            sbox(wopbs_key, byte_ct, true);
        });
        debug_state(state, round, cks, "sbox");

        add_round_key(sks, state, &encrypted_round_keys[round - 1]);
        debug_state(state, round, cks, "add round key");

        inv_mix_columns(sks, state, &zero);
        debug_state(state, round, cks, "inv mix columns");
    }

    inv_shift_rows(state);
    debug_state(state, 1, cks, "inv shift rows");

    state.par_iter_mut().for_each(|byte_ct| {
        sbox(wopbs_key, byte_ct, true);
    });
    debug_state(state, 1, cks, "sbox");

    add_round_key(sks, state, &encrypted_round_keys[0]);
    debug_state(state, 1, cks, "add round key");
}

fn debug_state(state: &Vec<BaseRadixCiphertext<Ciphertext>>, round: usize, cks: &RadixClientKey, function_name: &str) {
    let mut decrypted_state: Vec<u8> = Vec::new();
    for byte_ct in state {
        let decrypted_byte: u8 = cks.decrypt_without_padding(byte_ct);
        decrypted_state.push(decrypted_byte);
    }
    let hex_state: String = decrypted_state.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join("");
    println!("After {} in round {}: {}", function_name, round, hex_state);
}

fn add_round_key(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, round_key: &Vec<BaseRadixCiphertext<Ciphertext>>) {
    for (state_byte, round_key_byte) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_byte, round_key_byte);
    }
}

