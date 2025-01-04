use std::ops::Index;

use tfhe::shortint::backward_compatibility::client_key;
use tfhe::shortint::parameters::p_fail_2_minus_64::ks_pbs::PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64;
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

    test();

}

fn create_sbox_luts(
    server_key: &ServerKey
) 
-> (Vec<ManyLookupTable<Vec<u64>>>, Vec<ManyLookupTable<Vec<u64>>>, Vec<ManyLookupTable<Vec<u64>>>) {
    // Define the functions for the first set of S-box nibbles (first 16)
    let f1 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 0) as usize];
    let f2 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 1) as usize];
    let f3 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 2) as usize];
    let f4 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 3) as usize];
    let f5 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 4) as usize];
    let f6 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 5) as usize];
    let f7 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 6) as usize];
    let f8 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 7) as usize];

    let sbox_first_luts1: ManyLookupTable<Vec<u64>> = server_key.generate_many_lookup_table(&[
        &f1, &f2, &f3, &f4, &f5, &f6, &f7, &f8,
    ]);
    
    let f9 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 8) as usize];
    let f10 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 9) as usize];
    let f11 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 10) as usize];
    let f12 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 11) as usize];
    let f13 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 12) as usize];
    let f14 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 13) as usize];
    let f15 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 14) as usize];
    let f16 = |n: u64| table::SBOX_FIRST_NIBBLE[(n * 16 + 15) as usize];

    let sbox_first_luts2: ManyLookupTable<Vec<u64>> = server_key.generate_many_lookup_table(&[
        &f9, &f10, &f11, &f12, &f13, &f14, &f15, &f16,
    ]);

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

    let g1 = |n: u64| if n == 0 { 1 } else { 0 };
    let g2 = |n: u64| if n == 1 { 1 } else { 0 };
    let g3 = |n: u64| if n == 2 { 1 } else { 0 };
    let g4 = |n: u64| if n == 3 { 1 } else { 0 };
    let g5 = |n: u64| if n == 4 { 1 } else { 0 };
    let g6 = |n: u64| if n == 5 { 1 } else { 0 };
    let g7 = |n: u64| if n == 6 { 1 } else { 0 };
    let g8 = |n: u64| if n == 7 { 1 } else { 0 };

    let bitmap1 = server_key.generate_many_lookup_table(&[
        &g1, &g2, &g3, &g4, &g5, &g6, &g7, &g8,
    ]);

    let g9 = |n: u64| if n == 8 { 1 } else { 0 };
    let g10 = |n: u64| if n == 9 { 1 } else { 0 };
    let g11 = |n: u64| if n == 10 { 1 } else { 0 };
    let g12 = |n: u64| if n == 11 { 1 } else { 0 };
    let g13 = |n: u64| if n == 12 { 1 } else { 0 };
    let g14 = |n: u64| if n == 13 { 1 } else { 0 };
    let g15 = |n: u64| if n == 14 { 1 } else { 0 };
    let g16 = |n: u64| if n == 15 { 1 } else { 0 };

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

    let mut bitmap_vector: Vec<Ciphertext> = vec![];
    for lut in bitmap {
        let bitmap_lut = server_key.apply_many_lookup_table(&ct2, lut);
        bitmap_vector.extend(bitmap_lut);
    }

    // for i in 0..ct1_row.len() {
    //     server_key.unchecked_mul_lsb_assign(&mut ct1_row[i], &bitmap_vector[i]);
    // }

    // // add all the ciphertexts using add_assing, and store in vec0
    // for (i, mut row) in mul_vector.iter().enumerate() {
    //     let add = server_key.add_assign(row, &ct1_row[i]);
    //     ct1_row[i] = add;
    // }


    


    
    
    // Print the decrypted rows of ct1
    for (i, row) in bitmap_vector.iter().enumerate() {
        let dec_row = client_key.decrypt(row);
        println!("Row {}: {:?}", i, dec_row);
    }

    // Apply the second LUT to ct2
    // let ct2_new = server_key.apply_lookup_table(&ct2, &sbox_second_luts);

    // Return the new ciphertexts
    (ct1.clone(), ct2.clone())
}

fn test(){
    
    let (client_key, server_key) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);

    let (sbox_first_luts, sbox_second_luts, bitmap) = create_sbox_luts(&server_key);

    let msg1 = 1 as u64;
    let msg2 = 2 as u64;
    let ct1 = client_key.encrypt(msg1 as u64);
    let ct2 = client_key.encrypt(msg2 as u64);
    
    let start = std::time::Instant::now();
    let (ct1_new, ct2_new) = sub_bytes(&client_key, &server_key, &ct1, &ct2, &sbox_first_luts, &sbox_second_luts, &bitmap);
    let duration = start.elapsed();
    println!("Time elapsed in expensive_function() is: {:?}", duration);
}


