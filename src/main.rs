mod client;
mod server;
mod tables;
mod gpu;

use client::client::Client;
use server::server::Server;
use gpu::key_switch::{gpu_key_switch, cpu_key_switch};

use tfhe::core_crypto::gpu::cuda_keyswitch_lwe_ciphertext;
use tfhe::core_crypto::prelude::{LweCiphertextCount, LweCiphertextList, LweSize};
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

use tfhe::core_crypto::gpu::entities::lwe_keyswitch_key::CudaLweKeyswitchKey;
    use tfhe::core_crypto::gpu::{
        convert_lwe_keyswitch_key_async,
        vec::CudaVec,
        vec::GpuIndex,
        CudaStreams,
    };
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::ClientKey;

    use tfhe::shortint::gen_keys;
    use tfhe::integer::gen_keys_radix;
    use tfhe::shortint::wopbs::*;
    use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::shortint::prelude::LweDimension;
    use tfhe::core_crypto::algorithms::lwe_keyswitch;
    use tfhe::core_crypto::prelude::*;


fn example(){


    let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);

    let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));


    let pfksk = wopbs_key.cbs_pfpksk;
    let kskwopbs = wopbs_key.ksk_pbs_to_wopbs;
    let n1 = kskwopbs.input_key_lwe_dimension().0;
    let n2 = kskwopbs.output_key_lwe_dimension().0;
    let n3 = kskwopbs.output_lwe_size().0;
    println!("n1: {}, n2: {}, n3: {}", n1, n2, n3);


    // testing key switching -------


    let ksk: LweKeyswitchKey<Vec<u64>> = sks.key_switching_key;

    let ct1: LweCiphertext<Vec<u64>> = cks.encrypt(2).ct;
    let ct2 = cks.encrypt(3).ct;
    let ct3 = cks.encrypt(1).ct;

    let vec_lwe_in = vec![ct1, ct2, ct3];

    let cuda_vec_lwe_out = gpu_key_switch(&streams, &ksk, &vec_lwe_in);
    let gpu_vec_lwe_out = cuda_vec_lwe_out.to_lwe_ciphertext_list(&streams);
    let gpu_vec_out = gpu_vec_lwe_out.into_container();
    let start = std::time::Instant::now();
    let vec_lwe_out = cpu_key_switch(&ksk, &vec_lwe_in);
    println!("CPU key switch took: {:?}", start.elapsed());
    let mut vec_out = Vec::new();
    for lwe_out in vec_lwe_out.iter(){
        vec_out.extend(lwe_out.clone().into_container());
    }
    assert_eq!(vec_out, gpu_vec_out);

    // ----------------------------
    
    



 
}

// Main function to run the FHE AES CTR encryption. All functions, AES key expansion, encryption and decryption are run single threaded. Only CTR is parallelized.
fn main() {
    loop {
        example();
        break;
    }



    // Uncomment to run correctness tests
    
    // test();

    // let args = Args::parse();


    // let client_obj = Client::new(args.number_of_outputs, args.iv, args.key);

    // let (public_key, server_key, wopbs_key, encrypted_iv, encrypted_key) = client_obj.client_encrypt();

    // let server_obj = Server::new(public_key, server_key, wopbs_key);

    // // AES key expansion
    // let start = std::time::Instant::now();
    // let encrypted_round_keys: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = server_obj.aes_key_expansion(&encrypted_key);
    // let key_expansion_elapsed = start.elapsed();
    // println!("AES key expansion took: {:?}", key_expansion_elapsed);

    // // parallel AES CTR
    // let start_ctr = std::time::Instant::now();
    // let mut vec_fhe_encrypted_states: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = (0..args.number_of_outputs)
    // .into_par_iter()
    // .map(|i| {

    //     let mut state = encrypted_iv.clone();
    //     server_obj.add_scalar(&mut state, i as u128);
    //     server_obj.aes_encrypt(&encrypted_round_keys, &mut state);
    //     state
    // })
    // .collect();

    // let ctr_elapsed = start_ctr.elapsed();
    // println!("AES of #{:?} outputs computed in: {ctr_elapsed:?}", args.number_of_outputs);

    // // Client decrypts FHE computations and verifies correctness using aes crate.
    // client_obj.client_decrypt_and_verify(&mut vec_fhe_encrypted_states);

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