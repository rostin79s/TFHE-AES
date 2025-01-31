use std::{collections::HashMap};
use tfhe::{
    integer::{
        gen_keys_radix, wopbs::*,
    },
    shortint::parameters::{
        parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_0_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS, WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_0_KS_PBS, WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_8_CARRY_0_KS_PBS, WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_1_KS_PBS, WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_3_CARRY_0_KS_PBS, WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_4_CARRY_0_KS_PBS, WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_2_CARRY_0_KS_PBS, WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS, WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_0_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_1_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_3_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_4_KS_PBS, WOPBS_PARAM_MESSAGE_3_CARRY_0_KS_PBS, WOPBS_PARAM_MESSAGE_3_CARRY_1_KS_PBS, WOPBS_PARAM_MESSAGE_3_CARRY_2_KS_PBS, WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS, WOPBS_PARAM_MESSAGE_4_CARRY_0_KS_PBS
    },
};
use tfhe::integer::*;
use tfhe::shortint::*;

use tfhe::shortint::prelude::*;
use tfhe::shortint::parameters::DynamicDistribution;

mod tables;
use tables::table::SBOX;

pub const khar: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(589),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00015133150634020836,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(25),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(2),
    cbs_base_log: DecompositionBaseLog(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const sag: WopbsParameters = WopbsParameters {
    lwe_dimension: LweDimension(637),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.27510880527384e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(11),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


fn main() {

    let nb_block = 2;
    let (cks, sks) = gen_keys_radix(WOPBS_PARAM_MESSAGE_3_CARRY_0_KS_PBS, nb_block);




    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

    let modulus = cks.parameters().message_modulus().0;
    let carry = cks.parameters().carry_modulus().0;


    println!("Modulus: {}", modulus);
    println!("Carry: {}", carry);

    let mut moduli = 1_u64;
    for _ in 0..nb_block {
        moduli *= cks.parameters().message_modulus().0 as u64;
    }
    println!("Moduli: {}", moduli);

    let clear = 1 % moduli;
    let mut ct = cks.encrypt_without_padding(clear as u64);


    // let mut blocks: &mut [tfhe::shortint::Ciphertext] = ct.blocks_mut();
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    
    let lut = wopbs_key.generate_lut_radix_without_padding(&ct, |x| x as u64);

    let scal = cks.encrypt_without_padding(1 as u64);

    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);

    let start = std::time::Instant::now();

    let ct_res = wopbs_key.wopbs_without_padding(&ct, &lut);

    let elapsed = start.elapsed();
    println!("Time taken: {:?}", elapsed);



    let res: u64 = cks.decrypt_without_padding(&ct_res);
    println!("Result: {}", res);

    // assert_eq!(res, (clear * 2) % moduli)

}