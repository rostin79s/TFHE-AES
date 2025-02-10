use tfhe::shortint::Ciphertext;
use tfhe::integer::{ServerKey, ciphertext::BaseRadixCiphertext};

pub fn inv_mix_columns(sks: &ServerKey, mul_sbox_state: &mut Vec<Vec<BaseRadixCiphertext<Ciphertext>>>) -> Vec<BaseRadixCiphertext<Ciphertext>> {
    let mut state: Vec<BaseRadixCiphertext<Ciphertext>> = vec![];

    // mul9, mul11, mul13 and mul14 of each byte of state is stored in vector respectively.
    // We use them to do inverse mix columns operation, with max noise level of 4.
    for col in 0..4 {
        let base = col * 4;

        let s0 = &mul_sbox_state[base];
        let s1 = &mul_sbox_state[base + 1];
        let s2 = &mul_sbox_state[base + 2];
        let s3 = &mul_sbox_state[base + 3];

        state.push(sks.unchecked_add(
            &s0[3], // mul14(s0)
            &sks.unchecked_add(
                &s1[1], // mul11(s1)
                &sks.unchecked_add(&s2[2], // mul13(s2)
                    &s3[0] // mul9(s3)
                )
            )
        ));

        state.push(sks.unchecked_add(
            &s0[0], // mul9(s0)
            &sks.unchecked_add(
                &s1[3], // mul14(s1)
                &sks.unchecked_add(&s2[1], // mul11(s2)
                    &s3[2] // mul13(s3)
                )
            )
        ));

        state.push(sks.unchecked_add(
            &s0[2], // mul13(s0)
            &sks.unchecked_add(
                &s1[0], // mul9(s1)
                &sks.unchecked_add(&s2[3], // mul14(s2)
                    &s3[1] // mul11(s3)
                )
            )
        ));

        state.push(sks.unchecked_add(
            &s0[1], // mul11(s0)
            &sks.unchecked_add(
                &s1[2], // mul13(s1)
                &sks.unchecked_add(&s2[0], // mul9(s2)
                    &s3[3] // mul14(s3)
                )
            )
        ));
    }
    return state;
}
