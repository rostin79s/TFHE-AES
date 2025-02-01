use tfhe::integer::{wopbs::WopbsKey, RadixClientKey};

use super::*;

use std::sync::Arc;

pub fn AES_encrypt(cks: &RadixClientKey, sks: &ServerKey, wopbs_key: &WopbsKey, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>> , state: &mut Vec<BaseRadixCiphertext<Ciphertext>>){

    let rounds = 2;
    let state_size = 128; // AES works on 128-bit blocks
    let bytes_per_state = state_size / 8;

    add_round_key(sks,  state, &encrypted_round_keys[0]);

    for round in 1..rounds {

        let start = std::time::Instant::now();
        
        // for byte_ct in state.iter_mut() {
        //     sbox(cks, sks, wopbs_key, byte_ct);
        // }

        state.par_iter_mut().for_each(|byte_ct| {
            sbox(&wopbs_key, byte_ct);
        });

        println!("Sbox: {:?}", start.elapsed());



        

        // shift_rows(state);

  
        // let mut new_state: Vec<Ciphertext> = Vec::with_capacity(128);
        // for col in 0..4 {
        //     let mut column: Vec<Ciphertext> = Vec::with_capacity(32);
        //     for row in 0..4 {
        //         let index = row * 32 + col * 8;
        //         column.extend_from_slice(&state[index..index + 8]);
        //     }
        //     let mixed_column = mix_columns(sks, &column);
        //     new_state.extend_from_slice(&mixed_column);
        // }


        // state.clear();
        // state.extend_from_slice(&new_state);


      
        // add_round_key(sks, state, &encrypted_round_keys[round]);
    }

    
    // for byte_start in (0..bytes_per_state).map(|i| i * 8) {
    //     sbox(cks, sks, &mut state[byte_start..byte_start + 8]);
    // }

    // let state_mutex = Mutex::new(state.clone());
    //     (0..bytes_per_state).into_par_iter().for_each(|i| {
    //         let byte_start = i * 8;
    //         let mut state = state_mutex.lock().unwrap();
    //         sbox(cks, sks, &mut state[byte_start..byte_start + 8]);
    //     });
    // *state = state_mutex.into_inner().unwrap();


    // shift_rows(state);
    // add_round_key(sks, state, &encrypted_round_keys[rounds]);
}




fn add_round_key(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, round_key: &Vec<BaseRadixCiphertext<Ciphertext>>) {
    for (state_byte, round_key_byte) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_byte, round_key_byte);
    }
}

fn shift_rows(state: &mut Vec<Ciphertext>) {
    assert!(state.len() == 128, "State must have exactly 128 ciphertexts (16 bytes).");

    // Helper function to rotate a row of ciphertexts to the left by `shift` positions.
    fn rotate_left(row: &mut [Ciphertext], shift: usize) {
        let len = row.len();
        row.rotate_left(shift % len);
    }

    // Perform the ShiftRows transformation
    for row in 0..4 {
        // Each row corresponds to 4 bytes, which are 32 bits in the flattened state
        let start = row * 32; // Start index of the row
        let end = start + 32; // End index of the row
        let shift = row; // Row 0: 0 shift, Row 1: 1 shift, etc.
        rotate_left(&mut state[start..end], shift * 8); // Rotate left by (shift * 8) bits
    }
}
