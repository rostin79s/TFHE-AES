mod client;
mod server;
mod tables;

use client::client::Client;
use server::server::Server;

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::parameters::{LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_3_KS_PBS, LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS, V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64};
use tfhe::shortint::Ciphertext;

// To parse command-line arguments
use clap::Parser;

// To parallelize AES CTR
use rayon::prelude::*;

use rand::Rng;

/// Struct to define command-line arguments
#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_parser)]
    number_of_outputs: usize,

    #[arg(long, value_parser)]
    iv: u128,

    #[arg(long, value_parser)]
    key: u128,
}


fn example(){
    use tfhe::integer::gen_keys_radix;
    use tfhe::integer::wopbs::*;
    use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

    let nb_block = 4;
    //Generate the client key and the server key:
    let (cks, sks) = gen_keys_radix(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, nb_block);
    let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    // let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    let mut moduli = 1_u64;
    for _ in 0..nb_block {
        moduli *= cks.parameters().message_modulus().0;
    }
    println!("moduli: {}", moduli);

    let wopbs_key_short = wopbs_key.clone().into_raw_parts();
    let n2 = wopbs_key_short.ksk_pbs_to_wopbs
                    .output_key_lwe_dimension()
                    .to_lwe_size();
    let q = wopbs_key_short.param.ciphertext_modulus;
    println!("q: {}", q);
    println!("n2: {}", n2.0);


    let clear1 = 14 % moduli;
    let clear2 = 9 % moduli;
    let mut ct1 = cks.encrypt(clear1);
    let ct2 = cks.encrypt(clear2);
    sks.mul_assign_parallelized(&mut ct1, &ct2);

    // let mut ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);

    // sks.unchecked_scalar_add_assign(&mut ct1, 2);
    // let mut blocks = ct1.clone().into_blocks();
    // let sks_s = sks.into_raw_parts();
    // wopbs_key_short.wopbs_server_key.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // let ct1 = BaseRadixCiphertext::from_blocks(blocks);


    // let lut = wopbs_key.generate_lut_radix(&ct1, |x| x+1);
    // let ct_res = wopbs_key.wopbs(&ct1, &lut);
    // let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    let res: u64 = cks.decrypt(&ct1);

    println!("res: {}", res);
    assert_eq!(res, clear1 + clear2);

    // assert_eq!(res, clear1);
}

// Main function to run the FHE AES CTR encryption. All functions, AES key expansion, encryption and decryption are run single threaded. Only CTR is parallelized.
fn main() {
    loop {
        // example();
        break;
    }



    // Uncomment to run correctness tests
    
    // test();

    let args = Args::parse();


    let client_obj = Client::new(args.number_of_outputs, args.iv, args.key);

    let (public_key, server_key, wopbs_key, encrypted_iv, encrypted_key) = client_obj.client_encrypt();

    let server_obj = Server::new(public_key, server_key, wopbs_key);

    // AES key expansion
    let start = std::time::Instant::now();
    let encrypted_round_keys: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = server_obj.aes_key_expansion(&encrypted_key);
    let key_expansion_elapsed = start.elapsed();
    println!("AES key expansion took: {:?}", key_expansion_elapsed);

    // parallel AES CTR
    let start_ctr = std::time::Instant::now();
    let mut vec_fhe_encrypted_states: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = (0..args.number_of_outputs)
    .into_par_iter()
    .map(|i| {

        let mut state = encrypted_iv.clone();
        server_obj.add_scalar(&mut state, i as u128);
        server_obj.aes_encrypt(&encrypted_round_keys, &mut state);
        state
    })
    .collect();

    let ctr_elapsed = start_ctr.elapsed();
    println!("AES of #{:?} outputs computed in: {ctr_elapsed:?}", args.number_of_outputs);

    // Client decrypts FHE computations and verifies correctness using aes crate.
    client_obj.client_decrypt_and_verify(&mut vec_fhe_encrypted_states);

}

// function to test the correctness of the AES key expansion, encryption and decryption in FHE with test vectors and random test cases.
// Takes a long time since all functions are single threaded, lower security paramters to see correctness faster.
fn test() {
    // Define the test vectors
    let test_vectors = vec![
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a"
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "30c81c46a35ce411e5fbc1191a0a52ef"
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "f69f2445df4f9b17ad2b417be66c3710"
        ),
    ];
    // Test the test vectors
    for (key_hex, plain_hex) in test_vectors {
        
        let client_obj = Client::new(1, u128::from_str_radix(&plain_hex, 16).unwrap(), u128::from_str_radix(key_hex, 16).unwrap());

        let (public_key, server_key, wopbs_key, mut state, encrypted_key) = client_obj.client_encrypt();

        let server_obj = Server::new(public_key, server_key, wopbs_key);

        

        // Perform AES key expansion
        let encrypted_round_keys = server_obj.aes_key_expansion(&encrypted_key);

        // FHE computation of AES encryption and decryption
        server_obj.aes_encrypt(&encrypted_round_keys, &mut state);
        let mut state_dec = state.clone();
        server_obj.aes_decrypt(&encrypted_round_keys, &mut state_dec);

        // Verify FHE computation
        client_obj.test_verify(&state, &state_dec);
    }

    // Test random test cases
    let mut rng = rand::thread_rng();
    for _ in 0..10 {
        let key = rng.gen::<u128>();
        let plain = rng.gen::<u128>();

        let client_obj = Client::new(1, plain, key);

        let (public_key, server_key, wopbs_key, mut state, encrypted_key) = client_obj.client_encrypt();

        let server_obj = Server::new(public_key, server_key, wopbs_key);

        // Perform AES key expansion
        let encrypted_round_keys = server_obj.aes_key_expansion(&encrypted_key);

        // FHE computation of AES encryption and decryption
        server_obj.aes_encrypt(&encrypted_round_keys, &mut state);
        let mut state_dec = state.clone();
        server_obj.aes_decrypt(&encrypted_round_keys, &mut state_dec);

        // verify FHE computation
        client_obj.test_verify(&state, &state_dec);
    }
}