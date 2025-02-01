
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::gen_keys;
use super::*;

use tfhe::shortint::parameters::WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS;

pub fn mix_columns(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, zero: &BaseRadixCiphertext<Ciphertext>) {
    assert!(state.len() == 16, "State must have exactly 16 ciphertexts (16 bytes).");

    for col in 0..4 {
        let base = col * 4;
        
        let s0 = state[base].clone();
        let s1 = state[base + 1].clone();
        let s2 = state[base + 2].clone();
        let s3 = state[base + 3].clone();

        // Perform MixColumns transformation on this column
        state[base] = sks.unchecked_add(
            &mul2(sks, &s0, zero), 
            &sks.unchecked_add(
                &mul3(sks, &s1, zero), 
                &sks.unchecked_add(&s2, &s3)
            )
        );

        state[base + 1] = sks.unchecked_add(
            &s0,
            &sks.unchecked_add(
                &mul2(sks, &s1, zero),
                &sks.unchecked_add(
                    &mul3(sks, &s2, zero),
                    &s3
                )
            )
        );

        state[base + 2] = sks.unchecked_add(
            &s1,
            &sks.unchecked_add(
                &s0,
                &sks.unchecked_add(
                    &mul2(sks, &s2, zero),
                    &mul3(sks, &s3, zero)
                )
            )
        );

        state[base + 3] = sks.unchecked_add(
            &mul2(sks, &s3, zero),
            &sks.unchecked_add(
                &s2,
                &sks.unchecked_add(
                    &s1,
                    &mul3(sks, &s0, zero)
                )
            )
        );
    }
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