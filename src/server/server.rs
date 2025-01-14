use super::*;

pub fn AES_encrypt(cks: &ClientKey, sks: &ServerKey, encrypted_message_bits: &mut Vec<Ciphertext>, encrypted_round_keys: &[Vec<Ciphertext>; 11]){

    let rounds = 10;
    let state_size = 128; // AES works on 128-bit blocks
    let bytes_per_state = state_size / 8;

    add_round_key(sks,  encrypted_message_bits, &encrypted_round_keys[0]);

    for round in 1..rounds {
        // Apply S-Box substitution on each byte (8 ciphertexts)
        for byte_start in (0..bytes_per_state).map(|i| i * 8) {
            sbox(cks, sks, &mut encrypted_message_bits[byte_start..byte_start + 8]);
        }

        // Apply ShiftRows
        shift_rows(encrypted_message_bits);

        // Apply MixColumns
        for col in 0..4 {
            let col_start = col * 8;
            mix_columns(sks, &mut encrypted_message_bits[col_start..col_start + 8]);
        }

        // Add Round Key
        add_round_key(sks, encrypted_message_bits, &encrypted_round_keys[round]);
    }

    // Final round (no MixColumns)
    for byte_start in (0..bytes_per_state).map(|i| i * 8) {
        sbox(cks, sks, &mut encrypted_message_bits[byte_start..byte_start + 8]);
    }
    shift_rows(encrypted_message_bits);
    add_round_key(sks, encrypted_message_bits, &encrypted_round_keys[rounds]);
}




fn add_round_key(sks: &ServerKey, state: &mut Vec<Ciphertext>, round_key: &Vec<Ciphertext>) {
    for (state_bit, key_bit) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_bit, key_bit);
    }
}

fn shift_rows(state: &mut Vec<Ciphertext>) {
    let mut new_state: Vec<Option<Ciphertext>> = vec![None; state.len()];

    for row in 0..4 {
        for col in 0..4 {
            let new_col = (col + row) % 4;
            new_state[row * 4 + new_col] = Some(state[row * 4 + col].clone());
        }
    }

    *state = new_state.into_iter().map(|x| x.unwrap()).collect();
}
