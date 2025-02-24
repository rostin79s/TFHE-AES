mod client;
mod server;
mod tables;
mod gpu;

use client::client::Client;
use server::server::Server;
use gpu::key_switch::{gpu_key_switch, cpu_key_switch};

use tfhe::core_crypto::gpu::cuda_keyswitch_lwe_ciphertext;
use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use tfhe::core_crypto::prelude::{LweCiphertextCount, LweCiphertextList, LweSize};
use tfhe::integer::backward_compatibility::ciphertext;
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

use tfhe::core_crypto::gpu::algorithms::cuda_programmable_bootstrap_lwe_ciphertext;
use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use tfhe::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;

fn example(){



    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

    let pbs_params = V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;


    let small_lwe_dimension = pbs_params.lwe_dimension;
    let glwe_dimension = pbs_params.glwe_dimension;
    let polynomial_size = pbs_params.polynomial_size;

    let lwe_stddev = pbs_params.lwe_noise_distribution.gaussian_std_dev();
    let glwe_stddev = pbs_params.glwe_noise_distribution.gaussian_std_dev();

    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(lwe_stddev, 0.0);
    let glwe_noise_distribution =
        Gaussian::from_dispersion_parameter(glwe_stddev, 0.0);
    let pbs_base_log = pbs_params.pbs_base_log;
    let pbs_level = pbs_params.pbs_level;
    let ciphertext_modulus = pbs_params.ciphertext_modulus;


    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    println!("Generating keys...");


    let small_lwe_sk =
    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

    let glwe_sk =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_noise_distribution,
        ciphertext_modulus,
        seeder,
    );

    let std_bootstrapping_key: LweBootstrapKeyOwned<u64> = std_bootstrapping_key.decompress_into_lwe_bootstrap_key();
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);


    let message_modulus = pbs_params.message_modulus.0 * pbs_params.message_modulus.0;
    let delta = (1_u64 << 63) / message_modulus;

    let clear1 = 3u64;
    let plaintext1 = Plaintext(clear1 * delta);
    let ct1: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext1,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let clear2 = 5u64;
    let plaintext2 = Plaintext(clear2 * delta);
    let ct2: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext2,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let clear3 = 7u64;
    let plaintext3 = Plaintext(clear3 * delta);
    let ct3: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext3,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );



    let f = |x: u64| x * 2;

    let lut1: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus as usize,
        ciphertext_modulus,
        delta,
        f,
    );
    let lut2 = lut1.clone();
    let lut3 = lut1.clone();


    let mut ct1_out = LweCiphertext::new(
        0u64,
        big_lwe_sk.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    println!("Computing PBS...");
    let start = std::time::Instant::now();
    programmable_bootstrap_lwe_ciphertext(
        &ct1,
        &mut ct1_out,
        &lut1,
        &fourier_bsk,
    );
    println!("PBS took: {:?}", start.elapsed());


    let dec1: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, &ct1_out);
    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog((message_modulus.ilog2() + 1) as usize), DecompositionLevelCount(1));
    // println!("dec {:b}", dec1.0);
    // println!("scaled dec {:b}", signed_decomposer.closest_representable(dec1.0));
    let dec1: u64 =
        signed_decomposer.closest_representable(dec1.0) / delta;

    assert_eq!(f(clear1), dec1);

    // GPU --------------------------------

    let cuda_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(&std_bootstrapping_key, &streams);
    drop(std_bootstrapping_key);


    let mut vec_cts = vec![ct1.clone()];
    let size = 0;
    for _ in 0..size{
        vec_cts.push(ct1.clone());
    }

    let ciphertext_counts = vec_cts.len();
    let lwe_size = vec_cts[0].lwe_size();
    let mut cts_container = Vec::new();
    for lwe_in in vec_cts.iter(){
        cts_container.extend(lwe_in.clone().into_container());
    }

    let cts = LweCiphertextList::from_container(cts_container, lwe_size, ciphertext_modulus);

    let cuda_cts = CudaLweCiphertextList::from_lwe_ciphertext_list(&cts, &streams);
    let mut cuda_out_cts = CudaLweCiphertextList::new(big_lwe_sk.lwe_dimension(), LweCiphertextCount(ciphertext_counts), ciphertext_modulus, &streams);

    let mut vec_lut = vec![lut1.clone()];
    for _ in 0..size{
        vec_lut.push(lut1.clone());
    }

    let mut luts_container = Vec::new();
    for lut in vec_lut.iter(){
        luts_container.extend(lut.clone().into_container());
    }

    
    let luts = GlweCiphertextList::from_container(luts_container, vec_lut[0].glwe_size(), polynomial_size, ciphertext_modulus);
    let cuda_luts = CudaGlweCiphertextList::from_glwe_ciphertext_list(&luts, &streams);

    let index_vec: Vec<u64> = (0..vec_cts.len()).map(|x| x as u64).collect::<Vec<_>>();

    let input_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };
    let output_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };
    let lut_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };

    let start = std::time::Instant::now();
    cuda_programmable_bootstrap_lwe_ciphertext(&cuda_cts, &mut cuda_out_cts, &cuda_luts, &lut_indexes, &output_indexes, &input_indexes, LweCiphertextCount(ciphertext_counts), &cuda_bsk, &streams);
    println!("GPU PBS took: {:?}", start.elapsed());

    let gpu_vec_lwe_out = cuda_out_cts.to_lwe_ciphertext_list(&streams);
    let gpu_vec_out = gpu_vec_lwe_out.chunks(lwe_size.0).map(|lwe_out| {
        let temp = lwe_out.into_container().to_vec();
        LweCiphertextOwned::from_container(temp, ciphertext_modulus)
    }).collect::<Vec<_>>();
    
    for ct_out in gpu_vec_out.iter(){
        let dec: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, ct_out);
        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog((message_modulus.ilog2() + 1) as usize), DecompositionLevelCount(1));
        let dec: u64 =
            signed_decomposer.closest_representable(dec.0) / delta;
        assert_eq!(f(clear1), dec);
    }


   

    // -------------------


    // testing key switching -------

    let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);


    let ksk: LweKeyswitchKey<Vec<u64>> = sks.key_switching_key;
    let ct1: LweCiphertext<Vec<u64>> = cks.encrypt(2).ct;
    let ct2 = cks.encrypt(3).ct;
    let ct3 = cks.encrypt(1).ct;
    let vec_lwe_in = vec![ct1, ct2, ct3];

    let start = std::time::Instant::now();
    let cuda_vec_lwe_out = gpu_key_switch(&streams, &ksk, &vec_lwe_in);
    println!("GPU key switch took: {:?}", start.elapsed());
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