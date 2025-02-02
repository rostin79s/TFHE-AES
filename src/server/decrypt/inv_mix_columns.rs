use tfhe::integer::IntegerCiphertext;
use tfhe::shortint::Ciphertext;
use tfhe::integer::{ServerKey, ciphertext::BaseRadixCiphertext};

pub fn inv_mix_columns(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, zero: &BaseRadixCiphertext<Ciphertext>) {
    assert!(state.len() == 16, "State must have exactly 16 ciphertexts (16 bytes).");

    for col in 0..4 {
        let base = col * 4;

        let s0 = state[base].clone();
        let s1 = state[base + 1].clone();
        let s2 = state[base + 2].clone();
        let s3 = state[base + 3].clone();

        state[base] = sks.unchecked_add(
            &mul14(sks, &s0, zero),
            &sks.unchecked_add(
                &mul11(sks, &s1, zero),
                &sks.unchecked_add(&mul13(sks, &s2, zero), &mul9(sks, &s3, zero)),
            ),
        );

        state[base + 1] = sks.unchecked_add(
            &mul9(sks, &s0, zero),
            &sks.unchecked_add(
                &mul14(sks, &s1, zero),
                &sks.unchecked_add(&mul11(sks, &s2, zero), &mul13(sks, &s3, zero)),
            ),
        );

        state[base + 2] = sks.unchecked_add(
            &mul13(sks, &s0, zero),
            &sks.unchecked_add(
                &mul9(sks, &s1, zero),
                &sks.unchecked_add(&mul14(sks, &s2, zero), &mul11(sks, &s3, zero)),
            ),
        );

        state[base + 3] = sks.unchecked_add(
            &mul11(sks, &s0, zero),
            &sks.unchecked_add(
                &mul13(sks, &s1, zero),
                &sks.unchecked_add(&mul9(sks, &s2, zero), &mul14(sks, &s3, zero)),
            ),
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

fn mul9(sks: &ServerKey, ct: &BaseRadixCiphertext<Ciphertext>, zero: &BaseRadixCiphertext<Ciphertext>) -> BaseRadixCiphertext<Ciphertext> {
    // x * 9 = (((x * 2) * 2) * 2) + x
    let x2 = mul2(sks, ct, zero);
    let x4 = mul2(sks, &x2, zero);
    let x8 = mul2(sks, &x4, zero);
    sks.unchecked_add(&x8, ct)
}

fn mul11(sks: &ServerKey, ct: &BaseRadixCiphertext<Ciphertext>, zero: &BaseRadixCiphertext<Ciphertext>) -> BaseRadixCiphertext<Ciphertext> {
    // x * 11 = ((((x * 2) * 2) + x) * 2) + x
    let x2 = mul2(sks, ct, zero);
    let x4 = mul2(sks, &x2, zero);
    let x4_plus_x = sks.unchecked_add(&x4, ct);
    let x8_plus_x = mul2(sks, &x4_plus_x, zero);
    sks.unchecked_add(&x8_plus_x, ct)
}

fn mul13(sks: &ServerKey, ct: &BaseRadixCiphertext<Ciphertext>, zero: &BaseRadixCiphertext<Ciphertext>) -> BaseRadixCiphertext<Ciphertext> {
    // x * 13 = ((((x * 2) + x) * 2) * 2) + x
    let x2 = mul2(sks, ct, zero);
    let x2_plus_x = sks.unchecked_add(&x2, ct);
    let x4 = mul2(sks, &x2_plus_x, zero);
    let x8 = mul2(sks, &x4, zero);
    sks.unchecked_add(&x8, ct)
}

fn mul14(sks: &ServerKey, ct: &BaseRadixCiphertext<Ciphertext>, zero: &BaseRadixCiphertext<Ciphertext>) -> BaseRadixCiphertext<Ciphertext> {
    // x * 14 = ((((x * 2) + x) * 2) + x) * 2
    let x2 = mul2(sks, ct, zero);
    let x2_plus_x = sks.unchecked_add(&x2, ct);
    let x4_plus_x = mul2(sks, &x2_plus_x, zero);
    let x4_plus_x_plus_x = sks.unchecked_add(&x4_plus_x, ct);
    mul2(sks, &x4_plus_x_plus_x, zero)
}