mod client;
mod server;
mod tables;

use client::client::Client;
use server::server::Server;

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


fn example(){
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
    use tfhe::integer::wopbs::*;
    use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::shortint::prelude::LweDimension;
    use tfhe::core_crypto::algorithms::lwe_keyswitch;
    use tfhe::core_crypto::prelude::*;


    let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);


    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

    // let cks = ClientKey::new(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    // let sks = CudaServerKey::new(&cks, &streams);
    let ksk = sks.key_switching_key;


    let cuda_ksk = CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk, &streams);

    let ct1 = cks.encrypt(2).ct;
    let ct2 = cks.encrypt(3).ct;

    let lwe_size = ct1.lwe_size().0;
    let ciphertext_modulus = ct1.ciphertext_modulus();

    let ciphertext_counts = 2;

    let ct1_container = ct1.clone().into_container();
    let ct2_container = ct2.into_container();
    let mut cts_container = ct1_container.clone();
    cts_container.extend(ct2_container);

    let mut cts = LweCiphertextList::from_container(cts_container, LweSize(lwe_size), ciphertext_modulus);

    let out_lwe_size = ksk.output_lwe_size().0;
    
    let cuda_cts = CudaLweCiphertextList::from_lwe_ciphertext_list(&cts, &streams);
    let mut cuda_out_cts = CudaLweCiphertextList::new(LweDimension(out_lwe_size - 1), LweCiphertextCount(ciphertext_counts), ciphertext_modulus, &streams);

    let input_indexes = CudaVec::new(ciphertext_counts, &streams, gpu_index);
    let output_indexes: CudaVec<u64> = CudaVec::new(ciphertext_counts, &streams, gpu_index);


    cuda_keyswitch_lwe_ciphertext(&cuda_ksk, &cuda_cts, &mut cuda_out_cts, &input_indexes, &output_indexes, &streams);


    let mut out_ct1 = LweCiphertext::new(0, LweSize(out_lwe_size), ciphertext_modulus);

    keyswitch_lwe_ciphertext(&ksk, &ct1, &mut out_ct1);

    let data_out_ct1 = out_ct1.into_container();
    let intermediate_ct = cuda_out_cts.to_lwe_ciphertext_list(&streams);
    let date_cuda_out_cts = intermediate_ct.get(0).into_container();

    // assert
    assert_eq!(data_out_ct1, date_cuda_out_cts);

    // println!("data_out_ct1: {:?}", data_out_ct1);
    // println!("date_cuda_out_cts: {:?}", date_cuda_out_cts);

    // let clear1 = 2;
    // let mut ct1 = cks.encrypt(clear1);

    // let src = sks.key_switching_key;

    // let dest = CudaVec::new(len, streams, stream_index)

    // convert_lwe_keyswitch_key_async(streams, dest, src);
    // let f = |x: u64| x+1;
    // let lut = sks.generate_lookup_table(f);
    // let ct1 = sks.apply_lookup_table(&ct1,&lut);

    // let n = ct1.ct.lwe_size().0;
    // println!("n: {}", n);

    

    // let ct2 = cks.encrypt(clear2);

    // let mut ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
    // let n = ct1.blocks()[0].ct.lwe_size().0;
    // println!("n: {}", n);


    // sks.unchecked_scalar_add_assign(&mut ct1, 2);
    // let mut blocks = ct1.clone().into_blocks();
    // let sks_s = sks.into_raw_parts();
    // wopbs_key_short.wopbs_server_key.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // let ct1 = BaseRadixCiphertext::from_blocks(blocks);


    // let lut = wopbs_key.generate_lut_radix(&ct1, |x| x+1);
    // let ct_res = wopbs_key.wopbs(&ct1, &lut);
    // let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    // let res: u64 = cks.decrypt(&ct1);

    // println!("res: {}", res);
    // assert_eq!(res, clear1 + clear2);

    // assert_eq!(res, clear1);
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