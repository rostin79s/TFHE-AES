use tfhe::shortint::Ciphertext;
use tfhe::integer::{ServerKey, ciphertext::BaseRadixCiphertext};

pub fn mix_columns(sks: &ServerKey, mul_sbox_state: &mut Vec<Vec<BaseRadixCiphertext<Ciphertext>>>) -> Vec<BaseRadixCiphertext<Ciphertext>> {
    // we apply shifting rows first

    // Row 1: No shift

    // Row 2: Shift left by 1
    mul_sbox_state.swap(1, 5);
    mul_sbox_state.swap(5, 9);
    mul_sbox_state.swap(9, 13);

    // Row 3: Shift left by 2
    mul_sbox_state.swap(2, 10);
    mul_sbox_state.swap(6, 14);

    // Row 4: Shift left by 3
    mul_sbox_state.swap(3, 15);
    mul_sbox_state.swap(15, 11);
    mul_sbox_state.swap(11, 7);

    let mut state: Vec<BaseRadixCiphertext<Ciphertext>> = vec![];
    // Perform MixColumns transformation on this column, and create a new state and return it.
    // byte, mul2(byte), mul3(byte) are stored in a vector in that order. Max noise level 
    // is 4. 1 additional noise level due to the add round key before makes it 5 in total.
    for col in 0..4 {
        let base = col * 4;

        let s0 = &mul_sbox_state[base];
        let s1 = &mul_sbox_state[base + 1];
        let s2 = &mul_sbox_state[base + 2];
        let s3 = &mul_sbox_state[base + 3];

        
        state.push(sks.unchecked_add(
            &s0[1], // mul2(s0)
            &sks.unchecked_add(
                &s1[2], // mul3(s1)
                &sks.unchecked_add(&s2[0], &s3[0])
            )
        ));

        state.push(sks.unchecked_add(
            &s0[0],
            &sks.unchecked_add(
                &s1[1], // mul2(s1)
                &sks.unchecked_add(
                    &s2[2], // mul3(s2)
                    &s3[0]
                )
            )
        ));

        state.push(sks.unchecked_add(
            &s0[0],
            &sks.unchecked_add(
                &s1[0],
                &sks.unchecked_add(
                    &s2[1], // mul2(s2)
                    &s3[2]  // mul3(s3)
                )
            )
        ));

        state.push(sks.unchecked_add(
            &s0[2], // mul3(s0)
            &sks.unchecked_add(
                &s1[0],
                &sks.unchecked_add(
                    &s2[0],
                    &s3[1]  // mul2(s3)
                )
            )
        ));
    }
    return state;
}