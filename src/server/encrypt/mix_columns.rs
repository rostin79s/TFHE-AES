use tfhe::integer::IntegerCiphertext;
use tfhe::shortint::Ciphertext;
use tfhe::integer::{ServerKey, ciphertext::BaseRadixCiphertext};

pub fn mix_columns(sks: &ServerKey, mul_sbox_state: &mut Vec<Vec<BaseRadixCiphertext<Ciphertext>>>, zero: &BaseRadixCiphertext<Ciphertext>) -> Vec<BaseRadixCiphertext<Ciphertext>> {
    assert!(mul_sbox_state.len() == 16, "State must have exactly 16 ciphertexts (16 bytes).");

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
    for col in 0..4 {
        let base = col * 4;

        let s0 = &mul_sbox_state[base];
        let s1 = &mul_sbox_state[base + 1];
        let s2 = &mul_sbox_state[base + 2];
        let s3 = &mul_sbox_state[base + 3];

        // Perform MixColumns transformation on this column
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

fn mul2(sks: &ServerKey, ct: &BaseRadixCiphertext<Ciphertext>, zero: &BaseRadixCiphertext<Ciphertext>) -> BaseRadixCiphertext<Ciphertext> {

    let blocks = ct.blocks();
    let zero_b = zero.blocks();

    // let b1 = sks_s.unchecked_add(&blocks[0], &blocks[7]);
    // let b3 = sks_s.unchecked_add(&blocks[2], &blocks[7]);
    // let b4 = sks_s.unchecked_add(&blocks[3], &blocks[7]);

    // let new_blocks = vec![blocks[0].clone(), b1, blocks[2].clone(), b3, b4, blocks[4].clone(), blocks[5].clone(), blocks[6].clone()];
    let shifted_blocks = vec![blocks[7].clone(), blocks[0].clone(), blocks[1].clone(), blocks[2].clone(), blocks[3].clone(), blocks[4].clone(), blocks[5].clone(), blocks[6].clone()];

    let shifted_ctxt = &BaseRadixCiphertext::from_blocks(shifted_blocks);



    let new_blocks = vec![zero_b[0].clone(), blocks[7].clone(), zero_b[0].clone(), blocks[7].clone(), blocks[7].clone(), zero_b[0].clone(), zero_b[0].clone(), zero_b[0].clone()];

    let second_ctxt = &BaseRadixCiphertext::from_blocks(new_blocks);

    

    let new_blocks = sks.unchecked_add( second_ctxt, &shifted_ctxt);

    
    return new_blocks;

    
}

fn mul3(sks: &ServerKey, ct: &BaseRadixCiphertext<Ciphertext>, zero: &BaseRadixCiphertext<Ciphertext>) -> BaseRadixCiphertext<Ciphertext> {
    let mul2_res = mul2(sks, ct, zero);
    sks.unchecked_add(&mul2_res, ct)
}