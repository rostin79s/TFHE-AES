use tfhe::integer::{wopbs::WopbsKey, RadixClientKey};

use super::*;

use std::sync::Arc;

pub fn AES_encrypt(cks: &RadixClientKey, sks: &ServerKey, wopbs_key: &WopbsKey, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>> , state: &mut Vec<BaseRadixCiphertext<Ciphertext>>){

    let rounds = 2;
    let state_size = 128; // AES works on 128-bit blocks
    let bytes_per_state = state_size / 8;

    let zero = cks.encrypt_without_padding(0 as u64);

    add_round_key(sks,  state, &encrypted_round_keys[0]);

    for round in 1..rounds {

        let start = std::time::Instant::now();
        
        // for byte_ct in state.iter_mut() {
        //     sbox(cks, sks, wopbs_key, byte_ct);
        // }

        state.par_iter_mut().for_each(|byte_ct| {
            sbox(wopbs_key, byte_ct);
        });

        



        

        shift_rows(state);

  
        mix_columns(sks, state, &zero);

      
        add_round_key(sks, state, &encrypted_round_keys[round]);

        println!("Total: {:?}", start.elapsed());
    }

    
    // state.par_iter_mut().for_each(|byte_ct| {
    //     sbox(&wopbs_key, byte_ct);
    // });
    // shift_rows(state);
    // add_round_key(sks, state, &encrypted_round_keys[rounds]);
}




fn add_round_key(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, round_key: &Vec<BaseRadixCiphertext<Ciphertext>>) {
    for (state_byte, round_key_byte) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_byte, round_key_byte);
    }
}

fn shift_rows(state: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    assert!(state.len() == 16, "State must have exactly 16 ciphertexts (16 bytes).");

    // Row 2: Shift left by 1
    state.swap(1, 5);
    state.swap(5, 9);
    state.swap(9, 13);

    // Row 3: Shift left by 2
    state.swap(2, 10);
    state.swap(6, 14);

    // Row 4: Shift left by 3
    state.swap(3, 15);
    state.swap(15, 11);
    state.swap(11, 7);
}

