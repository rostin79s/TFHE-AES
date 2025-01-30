use std::{collections::HashMap};
use tfhe::{
    integer::{
        gen_keys_radix, wopbs::*,
    },
    shortint::parameters::{
        parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_0_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS, WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_0_KS_PBS, WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_8_CARRY_0_KS_PBS, WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_4_CARRY_0_KS_PBS, WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_2_CARRY_0_KS_PBS, WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_0_KS_PBS, WOPBS_PARAM_MESSAGE_4_CARRY_0_KS_PBS
    },
};
use tfhe::integer::*;
use tfhe::shortint::*;

mod tables;
use tables::table::SBOX;

fn main() {
    let nb_block = 8;
    //Generate the client key and the server key:
    let (cks, sks) = gen_keys_radix(WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, nb_block);

    // let (cks, sks) = gen_keys_radix(WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, nb_block);


    // let nb_block = 4;
    // //Generate the client key and the server key:
    // let (cks, sks) = gen_keys_radix(WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, nb_block);

    let (cks_s, sks_s) = gen_keys(WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS);




    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);
    let mut moduli = 1_u64;
    for _ in 0..nb_block {
        moduli *= cks.parameters().message_modulus().0 as u64;
    }
    println!("Moduli: {}", moduli);
    let clear = 0x00 % moduli;
    let mut ct = cks.encrypt(clear as u64);


    // let mut blocks: &mut [tfhe::shortint::Ciphertext] = ct.blocks_mut();
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    
    let lut = wopbs_key.generate_lut_radix(&ct, |x| SBOX[x as usize] as u64);

    // sks.unchecked_scalar_add_assign(&mut ct,1);


    let start = std::time::Instant::now();

    let ct_res = wopbs_key.wopbs(&ct, &lut);

    let elapsed = start.elapsed();
    println!("Time taken: {:?}", elapsed);



    let res: u64 = cks.decrypt(&ct_res);
    println!("Result: {}", res);

    // assert_eq!(res, (clear * 2) % moduli)

}