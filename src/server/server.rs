use super::*;

use std::sync::Arc;

pub fn AES_encrypt(cks: &ClientKey, sks: &ServerKey, encrypted_message_bits: &mut Vec<Ciphertext>, encrypted_round_keys: &Vec<Vec<Ciphertext>>){

    let rounds = 2;
    let state_size = 128; // AES works on 128-bit blocks
    let bytes_per_state = state_size / 8;

    add_round_key(sks,  encrypted_message_bits, &encrypted_round_keys[0]);

    for round in 1..rounds {
        
        for byte_start in (0..bytes_per_state).map(|i| i * 8) {
            sbox(cks, sks, &mut encrypted_message_bits[byte_start..byte_start + 8]);
        }

        // encrypted_message_bits
        // .par_chunks_mut(8)
        // .for_each(|chunk| {
        //     sbox(cks, sks, chunk); 
        // });



        

        // shift_rows(encrypted_message_bits);

  
        // let mut new_state: Vec<Ciphertext> = Vec::with_capacity(128);
        // for col in 0..4 {
        //     let mut column: Vec<Ciphertext> = Vec::with_capacity(32);
        //     for row in 0..4 {
        //         let index = row * 32 + col * 8;
        //         column.extend_from_slice(&encrypted_message_bits[index..index + 8]);
        //     }
        //     let mixed_column = mix_columns(sks, &column);
        //     new_state.extend_from_slice(&mixed_column);
        // }


        // encrypted_message_bits.clear();
        // encrypted_message_bits.extend_from_slice(&new_state);


      
        // add_round_key(sks, encrypted_message_bits, &encrypted_round_keys[round]);
    }

    
    // for byte_start in (0..bytes_per_state).map(|i| i * 8) {
    //     sbox(cks, sks, &mut encrypted_message_bits[byte_start..byte_start + 8]);
    // }

    // let encrypted_message_bits_mutex = Mutex::new(encrypted_message_bits.clone());
    //     (0..bytes_per_state).into_par_iter().for_each(|i| {
    //         let byte_start = i * 8;
    //         let mut encrypted_message_bits = encrypted_message_bits_mutex.lock().unwrap();
    //         sbox(cks, sks, &mut encrypted_message_bits[byte_start..byte_start + 8]);
    //     });
    // *encrypted_message_bits = encrypted_message_bits_mutex.into_inner().unwrap();


    // shift_rows(encrypted_message_bits);
    // add_round_key(sks, encrypted_message_bits, &encrypted_round_keys[rounds]);
}




fn add_round_key(sks: &ServerKey, state: &mut Vec<Ciphertext>, round_key: &Vec<Ciphertext>) {
    for (state_bit, key_bit) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_bit, key_bit);
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
