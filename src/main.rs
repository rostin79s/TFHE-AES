use std::ops::Index;

use tfhe::shortint::backward_compatibility::client_key;
use tfhe::shortint::parameters::p_fail_2_minus_64::ks_pbs::*;

use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M64, PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64, PARAM_MESSAGE_8_CARRY_0_COMPACT_PK_KS_PBS};
// use tfhe::shortint::parameters::{PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64, PARAM_MESSAGE_4_CARRY_0_KS_PBS};
// use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::circuit_bootstrap_boolean;
// use tfhe::shortint::wopbs::*;
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::{LookupTable, ManyLookupTable};
// use tfhe::
// use tfhe::core_crypto::prelude::test::TestResources;
// use tfhe::prelude::*;
mod table;


fn main() {
    // let start = std::time::Instant::now();
    // circuit_boot_vertical_packing();
    // let duration = start.elapsed();
    // println!("Time elapsed in expensive_function() is: {:?}", duration);

    // test();
    // sag();
    
    sbox();


}

fn and(l: &Ciphertext, r: &Ciphertext, shift: u8, lut: &LookupTable<Vec<u64>>, sks: &ServerKey, cks: &ClientKey) -> Ciphertext {
    let g = |x: u64| x%2;
    let lut2 = sks.generate_lookup_table(&g);
    let l = bootstrap(l, &lut2, &sks);

    let t = sks.unchecked_scalar_mul(&l, shift);
    // println!("T1: {}", cks.decrypt(&t));
    let t = sks.unchecked_add(&t, &r);
    // println!("T2: {}", cks.decrypt(&t));
    let t = sks.apply_lookup_table(&t, &lut);
    return t;
}

fn bootstrap(ct: &Ciphertext, lut: &LookupTable<Vec<u64>>, sks: &ServerKey) -> Ciphertext{
    return sks.apply_lookup_table(&ct, &lut);
}

fn sbox(){
    let (cks, sks) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);

    let x0 = cks.encrypt(1);
    let x1 = cks.encrypt(1);
    let x2 = cks.encrypt(0);
    let x3 = cks.encrypt(0);
    let x4 = cks.encrypt(0);
    let x5 = cks.encrypt(0);
    let x6 = cks.encrypt(0);
    let x7 = cks.encrypt(0);

    let f = |x: u64| (((x/8)%2) & (x%2) )%2;
    let lut = sks.generate_lookup_table(&f);

    let g = |x: u64| x%2;
    let lut2 = sks.generate_lookup_table(&g);


    let start = std::time::Instant::now();

    // Perform the linear transformations

    let x7 = bootstrap(&x7, &lut2, &sks);

    let y14 = sks.unchecked_add(&x3, &x5);
    let y14 = bootstrap(&y14, &lut2, &sks);

    let y13 = sks.unchecked_add(&x0, &x6);
    let y13 = bootstrap(&y13, &lut2, &sks);

    let y9 = sks.unchecked_add(&x0, &x3);
    let y9 = bootstrap(&y9, &lut2, &sks);

    let y8 = sks.unchecked_add(&x0, &x5);
    let y8 = bootstrap(&y8, &lut2, &sks);

    let t0 = sks.unchecked_add(&x1, &x2);
    let t0 = bootstrap(&t0, &lut2, &sks);

    let y1 = sks.unchecked_add(&t0, &x7); // 2

    let y4 = sks.unchecked_add(&y1, &x3);
    let y4 = bootstrap(&y4, &lut2, &sks);

    let y12 = sks.unchecked_add(&y13, &y14); // 2

    let y2 = sks.unchecked_add(&y1, &x0);
    let y2 = bootstrap(&y2, &lut2, &sks);

    let y5 = sks.unchecked_add(&y1, &x6);
    let y5 = bootstrap(&y5, &lut2, &sks);

    let y3 = sks.unchecked_add(&y5, &y8); // 2

    let t1 = sks.unchecked_add(&x4, &y12);
    let y15 = sks.unchecked_add(&t1, &x5);
    let y15 = bootstrap(&y15, &lut2, &sks);

    let y20 = sks.unchecked_add(&t1, &x1);

    let y6 = sks.unchecked_add(&y15, &x7); // 2

    let y10 = sks.unchecked_add(&y15, &t0); // 2

    let y11 = sks.unchecked_add(&y20, &y9); // 2

    let y7 = sks.unchecked_add(&x7, &y11); // 3


    let y17 = sks.unchecked_add(&y10, &y11); // 3
    let y19 = sks.unchecked_add(&y10, &y8); // 2

    let y16 = sks.unchecked_add(&t0, &y11); // 3

    let y21 = sks.unchecked_add(&y13, &y16); // 2

    let y18 = sks.unchecked_add(&x0, &y16);
    let y18 = bootstrap(&y18, &lut2, &sks);

    

    println!("Y Ciphertexts:");
    println!("y1 {}", cks.decrypt(&y1));
    println!("y2 {}", cks.decrypt(&y2));
    println!("y3 {}", cks.decrypt(&y3));
    println!("y4 {}", cks.decrypt(&y4));
    println!("y5 {}", cks.decrypt(&y5));
    println!("y6 {}", cks.decrypt(&y6));
    println!("y7 {}", cks.decrypt(&y7));
    println!("y8 {}", cks.decrypt(&y8));
    println!("y9 {}", cks.decrypt(&y9));
    println!("y10 {}", cks.decrypt(&y10));
    println!("y11 {}", cks.decrypt(&y11));
    println!("y12 {}", cks.decrypt(&y12));
    println!("y13 {}", cks.decrypt(&y13));
    println!("y14 {}", cks.decrypt(&y14));
    println!("y15 {}", cks.decrypt(&y15));
    println!("y16 {}", cks.decrypt(&y16));
    println!("y17 {}", cks.decrypt(&y17));
    println!("y18 {}", cks.decrypt(&y18));
    println!("y19 {}", cks.decrypt(&y19));
    println!("y20 {}", cks.decrypt(&y20));
    println!("y21 {}", cks.decrypt(&y21));


    // middle non-linear layer
    

   
    let t2 = and(&y12, &y15, 8, &lut, &sks, &cks); // 1
    let t3 = and(&y3, &y6, 8, &lut, &sks, &cks); // 1
    let t4 = sks.unchecked_add(&t3, &t2); // 2
    let t5 = and(&y4,&x7, 8, &lut, &sks, &cks); // 1
    let t6 = sks.unchecked_add(&t5, &t2); // 2

    
    let t7 = and(&y13,&y16, 8, &lut, &sks, &cks); // 1
    let t8 = and(&y5,&y1, 8, &lut, &sks, &cks); // 1
    let t9 = sks.unchecked_add(&t8, &t7); // 2
    let t10 = and(&y2,&y7, 8, &lut, &sks, &cks); // 1
    let t11 = sks.unchecked_add(&t10, &t7); // 2
    let t12 = and(&y9,&y11, 8, &lut, &sks, &cks); // 1
    let t13 = and(&y14,&y17, 8, &lut, &sks, &cks); // 1
    let t14 = sks.unchecked_add(&t13, &t12); // 2


  
    let t15 = and(&y8,&y10, 8, &lut, &sks, &cks); // 1
    let t16 = sks.unchecked_add(&t15, &t12); // 2
    let t17 = sks.unchecked_add(&t4, &t14); // 4
    let t18 = sks.unchecked_add(&t6, &t16); // 4
    let t19 = sks.unchecked_add(&t9, &t14); // 4
    let t20 = sks.unchecked_add(&t11, &t16); // 4
    let t21 = sks.unchecked_add(&t17, &y20); // 16+
    let t22 = sks.unchecked_add(&t18, &y19); // 6 
    let t23 = sks.unchecked_add(&t19, &y21); // 6 
    let t24 = sks.unchecked_add(&t20, &y18); // 5
    let t25 = sks.unchecked_add(&t21, &t22); // 16+

    
    let t26 = and(&t21,&t23, 8, &lut, &sks, &cks); // 1

    let t27 = sks.unchecked_add(&t24, &t26); // 6

    let t28 = and(&t25, &t27, 8, &lut, &sks, &cks); // 1

    let t29 = sks.unchecked_add(&t28, &t22); // 7
    let t30 = sks.unchecked_add(&t23, &t24); // 11
    let t31 = sks.unchecked_add(&t22, &t26); // 7

    let t32 = and(&t30, &t31, 8, &lut, &sks, &cks); // 1
    
    let t33 = sks.unchecked_add(&t32, &t24); // 6
    let t34 = sks.unchecked_add(&t23, &t33); // 12
    let t35 = sks.unchecked_add(&t27, &t33); // 12

    let t36 = and(&t35, &t24, 8, &lut, &sks, &cks); // 1

    let t37 = sks.unchecked_add(&t36, &t34); // 19
    let t38 = sks.unchecked_add(&t27, &t36); // 7

    let t39 = and(&t29, &t38, 8, &lut, &sks, &cks); // 1


    let t40 = sks.unchecked_add(&t25, &t39);
    let t41 = sks.unchecked_add(&t40, &t37);
    let t42 = sks.unchecked_add(&t29, &t33);
    let t43 = sks.unchecked_add(&t29, &t40);
    let t44 = sks.unchecked_add(&t33, &t37);
    let t45 = sks.unchecked_add(&t42, &t41);

    println!("T Ciphertexts:");
    println!("t40 {}", cks.decrypt(&t40));
    println!("t41 {}", cks.decrypt(&t41));
    println!("t42 {}", cks.decrypt(&t42));
    println!("t43 {}", cks.decrypt(&t43));
    println!("t44 {}", cks.decrypt(&t44));
    println!("t45 {}", cks.decrypt(&t45));

    let shift = 8;
    
    let z0 = and(&t44, &y15, shift, &lut, &sks, &cks);
    let z1 = and(&t37, &y6, shift, &lut, &sks, &cks);
    let z2 = and(&t33, &x7, shift, &lut, &sks, &cks);
    let z3 = and(&t43, &y16, shift, &lut, &sks, &cks);
    let z4 = and(&t40, &y1, shift, &lut, &sks, &cks);
    let z5 = and(&t29, &y7, shift, &lut, &sks, &cks);
    let z6 = and(&t42, &y11, shift, &lut, &sks, &cks);
    let z7 = and(&t45, &y17, shift, &lut, &sks, &cks);
    let z8 = and(&t41, &y10, shift, &lut, &sks, &cks);
    let z9 = and(&t44, &y12, shift, &lut, &sks, &cks);
    let z10 = and(&t37, &y3, shift, &lut, &sks, &cks);
    let z11 = and(&t33, &y4, shift, &lut, &sks, &cks);
    let z12 = and(&t43, &y13, shift, &lut, &sks, &cks);
    let z13 = and(&t40, &y5, shift, &lut, &sks, &cks);
    let z14 = and(&t29, &y2, shift, &lut, &sks, &cks);
    let z15 = and(&t42, &y9, shift, &lut, &sks, &cks);
    let z16 = and(&t45, &y14, shift, &lut, &sks, &cks);
    let z17 = and(&t41, &y8, shift, &lut, &sks, &cks);


    println!("Z Ciphertexts:");
    println!("z0: {}", cks.decrypt(&z0));
    println!("z1: {}", cks.decrypt(&z1));
    println!("z2: {}", cks.decrypt(&z2));
    println!("z3: {}", cks.decrypt(&z3));
    println!("z4: {}", cks.decrypt(&z4));
    println!("z5: {}", cks.decrypt(&z5));
    println!("z6: {}", cks.decrypt(&z6));
    println!("z7: {}", cks.decrypt(&z7));
    println!("z8: {}", cks.decrypt(&z8));
    println!("z9: {}", cks.decrypt(&z9));
    println!("z10: {}", cks.decrypt(&z10));
    println!("z11: {}", cks.decrypt(&z11));
    println!("z12: {}", cks.decrypt(&z12));
    println!("z13: {}", cks.decrypt(&z13));
    println!("z14: {}", cks.decrypt(&z14));
    println!("z15: {}", cks.decrypt(&z15));
    println!("z16: {}", cks.decrypt(&z16));
    println!("z17: {}", cks.decrypt(&z17));



    // third linear layer
    
    let t46 = sks.unchecked_add(&z15, &z16);
    let t47 = sks.unchecked_add(&z10, &z11);
    let t48 = sks.unchecked_add(&z5, &z13);
    let t49 = sks.unchecked_add(&z9, &z10);
    let t50 = sks.unchecked_add(&z2, &z12);
    let t51 = sks.unchecked_add(&z2, &z5);
    let t52 = sks.unchecked_add(&z7, &z8);
    let t53 = sks.unchecked_add(&z0, &z3);
    let t54 = sks.unchecked_add(&z6, &z7);
    let t55 = sks.unchecked_add(&z16, &z17);
    let t56 = sks.unchecked_add(&z12, &t48);
    let t57 = sks.unchecked_add(&t50, &t53);
    let t58 = sks.unchecked_add(&z4, &t46);
    let t59 = sks.unchecked_add(&z3, &t54);
    let t60 = sks.unchecked_add(&t46, &t57);
    let t61 = sks.unchecked_add(&z14, &t57);
    let t62 = sks.unchecked_add(&t52, &t58);
    let t63 = sks.unchecked_add(&t49, &t58);
    let t64 = sks.unchecked_add(&z4, &t59);
    let t65 = sks.unchecked_add(&t61, &t62);
    let t66 = sks.unchecked_add(&z1, &t63);

    println!("T Ciphertexts:");
    println!("t46: {}", cks.decrypt(&t46));
    println!("t47: {}", cks.decrypt(&t47));
    println!("t48: {}", cks.decrypt(&t48));
    println!("t49: {}", cks.decrypt(&t49));
    println!("t50: {}", cks.decrypt(&t50));
    println!("t51: {}", cks.decrypt(&t51));
    println!("t59: {}", cks.decrypt(&t59));
    println!("t63: {}", cks.decrypt(&t63));
    let s0 = sks.unchecked_add(&t59, &t63);
    let s6 = sks.unchecked_scalar_add(&sks.unchecked_add(&t56, &t62),1);
    let s7 = sks.unchecked_scalar_add(&sks.unchecked_add(&t48, &t60),1);
    let t67 = sks.unchecked_add(&t64, &t65);
    let s3 = sks.unchecked_add(&t53, &t66);
    let s4 = sks.unchecked_add(&t51, &t66);
    let s5 = sks.unchecked_add(&t47, &t65);
    let s1 = sks.unchecked_scalar_add(&sks.unchecked_add(&t64, &s3),1);
    let s2 = sks.unchecked_scalar_add(&sks.unchecked_add(&t55, &t67),1);

    let s0 = bootstrap(&s0, &lut2, &sks);
    let s1 = bootstrap(&s1, &lut2, &sks);
    let s2 = bootstrap(&s2, &lut2, &sks);
    let s3 = bootstrap(&s3, &lut2, &sks);
    let s4 = bootstrap(&s4, &lut2, &sks);
    let s5 = bootstrap(&s5, &lut2, &sks);
    let s6 = bootstrap(&s6, &lut2, &sks);
    let s7 = bootstrap(&s7, &lut2, &sks);
    

    println!("Decrypted S-Box Results:");
    println!("s0: {}", cks.decrypt(&s0)%2);
    println!("s1: {}", cks.decrypt(&s1)%2);
    println!("s2: {}", cks.decrypt(&s2)%2);
    println!("s3: {}", cks.decrypt(&s3)%2);
    println!("s4: {}", cks.decrypt(&s4)%2);
    println!("s5: {}", cks.decrypt(&s5)%2);
    println!("s6: {}", cks.decrypt(&s6)%2);
    println!("s7: {}", cks.decrypt(&s7)%2);
    


    let end = std::time::Instant::now();
    let duration = end.duration_since(start);
    println!("Time elapsed in expensive_function() is: {:?}", duration);

    // Decrypt and print the results

    // println!("Decrypted S-Box Results:");
    // println!("y14: {}", cks.decrypt(&y14)%2);
    // println!("y13: {}", cks.decrypt(&y13)%2);
    // println!("y9: {}", cks.decrypt(&y9)%2);
    // println!("y8: {}", cks.decrypt(&y8)%2);
    // println!("t0: {}", cks.decrypt(&t0)%2);
    // println!("y1: {}", cks.decrypt(&y1)%2);
    // println!("y4: {}", cks.decrypt(&y4)%2);
    // println!("y12: {}", cks.decrypt(&y12)%2);
    // println!("y2: {}", cks.decrypt(&y2)%2);
    // println!("y5: {}", cks.decrypt(&y5)%2);
    // println!("y3: {}", cks.decrypt(&y3)%2);
    // println!("t1: {}", cks.decrypt(&t1)%2);
    // println!("y15: {}", cks.decrypt(&y15)%2);
    // println!("y20: {}", cks.decrypt(&y20)%2);
    // println!("y6: {}", cks.decrypt(&y6)%2);
    // println!("y10: {}", cks.decrypt(&y10)%2);
    // println!("y11: {}", cks.decrypt(&y11)%2);
    // println!("y7: {}", cks.decrypt(&y7)%2);
    // println!("y17: {}", cks.decrypt(&y17)%2);
    // println!("y19: {}", cks.decrypt(&y19)%2);
    // println!("y16: {}", cks.decrypt(&y16)%2);
    // println!("y21: {}", cks.decrypt(&y21)%2);
    // println!("y18: {}", cks.decrypt(&y18)%2);

}

fn sag(){
    // let (cks, sks) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);
    let (cks, sks) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);

    let msg1 = 15;

    let msg2 = 6;

    let mut ct1 = cks.encrypt(msg1);
    let ct2 = cks.encrypt(msg2);
    let deg = ct1.degree;
    println!("Degree: {:?}", deg);

    let f = |n: u64| n;
    let lut = sks.generate_lookup_table(&f);

    let start = std::time::Instant::now();

    // sks.apply_lookup_table_assign(&mut ct1, &lut);

    // sks.unchecked_scalar_mul_assign(&mut ct1, 8);
    sks.unchecked_add_assign(&mut ct1, &ct2);
    // sks.unchecked_add_assign(&mut ct1, &ct2);
    let deg = ct1.degree;
    println!("Degree: {:?}", deg);
    sks.apply_lookup_table_assign(&mut ct1, &lut);

    sks.unchecked_scalar_mul_assign(&mut ct1, 8);



    let duration = start.elapsed();
    println!("Time elapsed in expensive_function() is: {:?}", duration);

    let dec = cks.decrypt(&ct1);
    println!("Decrypted: {:?}", dec);



    // let f1 = |x: u64| x.pow(2)%16;
    // let f2 = |x: u64| x.count_ones() as u64;
    // let f3 = |x: u64| x*5;
    // let f4 = |x: u64| x-2;
    // let f5 = |x: u64| x-1;


    // let start = std::time::Instant::now();

    // let functions:&[&dyn Fn(u64) -> u64] = &[&f1, &f2, &f3, &f4];

    // let luts = sks.generate_many_lookup_table(functions);
    // let max = luts.input_max_degree;
    // println!("Max: {:?}", max);
    
    // let vec_res = sks.apply_many_lookup_table(&ct, &luts);

    // let duration = start.elapsed();
    // println!("Time elapsed in expensive_function() is: {:?}", duration);


    // let functions: &[&dyn Fn(u64) -> u64] = functions;
    // for (res, function) in vec_res.iter().zip(functions) {
    //     let dec = cks.decrypt(res);
    //     println!("Decrypted: {:?}", dec);
    //     // assert_eq!(dec, function(msg));
    // }
}

fn create_sbox_luts(
    server_key: &ServerKey
) 
-> (Vec<ManyLookupTable<Vec<u64>>>, Vec<ManyLookupTable<Vec<u64>>>, Vec<ManyLookupTable<Vec<u64>>>) {
    // Define the functions for the first set of S-box nibbles (first 16)
    let f1 = |n: u64| n-1;
    let f2 = |n: u64| n-2;
    let f3 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 2) as usize] %16;
    let f4 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 3) as usize] %16;
    let f5 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 4) as usize] %16;
    let f6 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 5) as usize] %16;
    let f7 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 6) as usize] %16;
    let f8 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 7) as usize] %16;

    let sbox_first_luts1: ManyLookupTable<Vec<u64>> = server_key.generate_many_lookup_table(&[
        &f1, &f2,&f3
    ]);
    
    let f9 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 8) as usize] %16;
    let f10 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 9) as usize] %16;
    let f11 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 10) as usize] %16;
    let f12 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 11) as usize] %16;
    let f13 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 12) as usize] %16;
    let f14 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 13) as usize] %16;
    let f15 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 14) as usize] %16;
    let f16 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 15) as usize] %16;

    let sbox_first_luts2: ManyLookupTable<Vec<u64>> = server_key.generate_many_lookup_table(&[
        &f2
    ]);
    // server_key.
    // Define the functions for the second set of S-box nibbles (second 16)
    let f17 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 0) as usize];
    let f18 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 1) as usize];
    let f19 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 2) as usize];
    let f20 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 3) as usize];
    let f21 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 4) as usize];
    let f22 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 5) as usize];
    let f23 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 6) as usize];
    let f24 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 7) as usize];

    let sbox_second_luts1: ManyLookupTable<Vec<u64>> = server_key.generate_many_lookup_table(&[
        &f17, &f18, &f19, &f20, &f21, &f22, &f23, &f24,
    ]);

    let f25 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 8) as usize];
    let f26 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 9) as usize];
    let f27 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 10) as usize];
    let f28 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 11) as usize];
    let f29 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 12) as usize];
    let f30 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 13) as usize];
    let f31 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 14) as usize];
    let f32 = |n: u64| table::SBOX_SECOND_NIBBLE[(n * 16 + 15) as usize];

    let sbox_second_luts2: ManyLookupTable<Vec<u64>> = server_key.generate_many_lookup_table(&[
        &f25, &f26, &f27, &f28, &f29, &f30, &f31, &f32,
    ]);

    let g1 = |n: u64| n%16;
    let g2 = |n: u64| (n-1)%16;
    let g3 = |n: u64| n%16;
    let g4 = |n: u64| n%16;
    let g5 = |n: u64| n%16;
    let g6 = |n: u64| n%16;
    let g7 = |n: u64| n%16;
    let g8 = |n: u64| n%16;
    
    let bitmap1 = server_key.generate_many_lookup_table(&[
        &g1, &g2, &g3, &g4, &g5, &g6, &g7, &g8,
    ]);
    
    let g9 = |n: u64| n%16;
    let g10 = |n: u64| n%16;
    let g11 = |n: u64| n%16;
    let g12 = |n: u64| n%16;
    let g13 = |n: u64| n%16;
    let g14 = |n: u64| n%16;
    let g15 = |n: u64| n%16;
    let g16 = |n: u64| n%16;

    let bitmap2 = server_key.generate_many_lookup_table(&[
        &g9, &g10, &g11, &g12, &g13, &g14, &g15, &g16,
    ]);

    // Return the two vectors of LUTs
    (
        vec![sbox_first_luts1, sbox_first_luts2], 
        vec![sbox_second_luts1, sbox_second_luts2],
        vec![bitmap1, bitmap2]
    )
}

fn sub_bytes(
    client_key: &ClientKey,
    server_key: &ServerKey,
    ct1: &Ciphertext,
    ct2: &Ciphertext,
    sbox_first_luts: &Vec<ManyLookupTable<Vec<u64>>>,
    sbox_second_luts: &Vec<ManyLookupTable<Vec<u64>>>,
    bitmap: &Vec<ManyLookupTable<Vec<u64>>>,
) -> (Ciphertext, Ciphertext) {
    // Apply the first LUT to ct1
    let mut ct1_row: Vec<Ciphertext> = vec![];
    for lut in sbox_first_luts {
        let ct1_lut = server_key.apply_many_lookup_table(&ct1, lut);
        ct1_row.extend(ct1_lut);
    }
    let sag = ct2.degree;
    println!("SAG: {:?}", sag);

    // let mut bitmap_vector: Vec<Ciphertext> = vec![];
    // for lut in bitmap {
    //     let bitmap_lut = server_key.apply_many_lookup_table(&ct2, lut);
    //     bitmap_vector.extend(bitmap_lut);
    // }

    // for i in 0..ct1_row.len() {
    //     server_key.unchecked_mul_lsb_assign(&mut ct1_row[i], &bitmap_vector[i]);
    // }

    // // add all the ciphertexts using add_assing, and store in vec0
    // for (i, mut row) in mul_vector.iter().enumerate() {
    //     let add = server_key.add_assign(row, &ct1_row[i]);
    //     ct1_row[i] = add;
    // }





    
    
    // Print the decrypted rows of ct1
    // for (i, row) in bitmap_vector.iter().enumerate() {
    //     let dec_row = client_key.decrypt(row);
    //     println!("Row {}: {:?}", i, dec_row);
    // }

    for (i, row) in ct1_row.iter().enumerate() {
        let dec_row = client_key.decrypt(row);
        println!("Row {}: {:?}", i, dec_row);
    }

    // Apply the second LUT to ct2
    // let ct2_new = server_key.apply_lookup_table(&ct2, &sbox_second_luts);

    // Return the new ciphertexts
    (ct1.clone(), ct2.clone())
}

fn test(){
    
    let (client_key, server_key) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64);
    // let (client_key, server_key) = gen_keys(PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);

    let (sbox_first_luts, sbox_second_luts, bitmap) = create_sbox_luts(&server_key);

    let msg1 = 11 as u64;
    let msg2 = 2 as u64;
    let ct1 = client_key.encrypt(msg1 as u64);
    let ct2 = client_key.encrypt(msg2 as u64);
    
    let start = std::time::Instant::now();
    let (ct1_new, ct2_new) = sub_bytes(&client_key, &server_key, &ct1, &ct2, &sbox_first_luts, &sbox_second_luts, &bitmap);
    let duration = start.elapsed();
    println!("Time elapsed in expensive_function() is: {:?}", duration);
}


