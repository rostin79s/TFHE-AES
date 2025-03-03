mod client;
mod server;
mod tables;
mod gpu;

use client::client::Client;
use gpu::cbs_vp::cpu_cbc_vp;
use gpu::pbs::{gpu_multi_pbs, gpu_pbs};
use server::server::Server;
use gpu::key_switch::{gpu_key_switch, cpu_key_switch};
use gpu::extract_bits::{cpu_extract_bits, gpu_extract_bits};

use tfhe::core_crypto::commons::math::random::BoundedDistribution;
use tfhe::core_crypto::gpu::cuda_keyswitch_lwe_ciphertext;
use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use tfhe::core_crypto::prelude::{LweCiphertextCount, LweCiphertextList, LweSize};
use tfhe::integer::backward_compatibility::ciphertext;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::parameters::{LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_3_KS_PBS, LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS, PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64};
use tfhe::shortint::Ciphertext;

// To parse command-line arguments
use clap::Parser;

// To parallelize AES CTR
use rayon::prelude::*;

use rand::Rng;

//  Struct to define command-line arguments
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
use tfhe::core_crypto::gpu::cuda_multi_bit_programmable_bootstrap_lwe_ciphertext;

fn example(){



    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

    // let pbs_params = V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

    let pbs_params = PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;


    let small_lwe_dimension = pbs_params.lwe_dimension;
    let glwe_dimension = pbs_params.glwe_dimension;
    let polynomial_size = pbs_params.polynomial_size;

    let lwe_stddev = pbs_params.lwe_noise_distribution.gaussian_std_dev();
    let glwe_stddev = pbs_params.glwe_noise_distribution.gaussian_std_dev();
    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(lwe_stddev, 0.0);
    let glwe_noise_distribution =
        Gaussian::from_dispersion_parameter(glwe_stddev, 0.0);

    // let lwe_noise_distribution =
    // DynamicDistribution::new_t_uniform(46);
    // let glwe_noise_distribution =
    // DynamicDistribution::new_t_uniform(17);

    let pbs_base_log = pbs_params.pbs_base_log;
    let pbs_level = pbs_params.pbs_level;
    let ciphertext_modulus = pbs_params.ciphertext_modulus;


    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    println!("Generating keys right now...");


    let small_lwe_sk =
    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

    let glwe_sk =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();


    let decomp_base_log = pbs_params.ks_base_log;
    let decomp_level_count = pbs_params.ks_level;

    let mut ksk = LweKeyswitchKey::new(
    0u64,
    decomp_base_log,
    decomp_level_count,
    big_lwe_sk.lwe_dimension(),
    small_lwe_sk.lwe_dimension(),
    ciphertext_modulus,
    );

    generate_lwe_keyswitch_key(
    &big_lwe_sk,
    &small_lwe_sk,
    &mut ksk,
    lwe_noise_distribution,
    &mut encryption_generator,
    );

    assert!(!ksk.as_ref().iter().all(|&x| x == 0));



    // let bsk = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
    //     &small_lwe_sk,
    //     &glwe_sk,
    //     pbs_base_log,
    //     pbs_level,
    //     glwe_noise_distribution,
    //     ciphertext_modulus,
    //     seeder,
    // );

    // let bsk: LweBootstrapKeyOwned<u64> = bsk.decompress_into_lwe_bootstrap_key();
    // let mut fourier_bsk = FourierLweBootstrapKey::new(
    //     bsk.input_lwe_dimension(),
    //     bsk.glwe_size(),
    //     bsk.polynomial_size(),
    //     bsk.decomposition_base_log(),
    //     bsk.decomposition_level_count(),
    // );
    // convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);



    let grouping_factor = pbs_params.grouping_factor;
    let mut bsk = LweMultiBitBootstrapKey::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
        small_lwe_dimension,
        grouping_factor,
        ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        &mut bsk,
        glwe_noise_distribution,
        &mut encryption_generator,
    );

    let mut multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.grouping_factor(),
    );

    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut multi_bit_bsk);


    let message_modulus = pbs_params.message_modulus.0 * pbs_params.message_modulus.0;
    let delta = (1_u64 << 63) / message_modulus;


    let clear1 = 11u64;
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



    let f = |x: u64| x;

    let lut1: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus as usize,
        ciphertext_modulus,
        delta,
        f,
    );
    let g = |x: u64| x + 3;
    let lut2 = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus as usize,
        ciphertext_modulus,
        delta,
        g,
    );
    let lut3 = lut1.clone();


    let mut ct1_out = LweCiphertext::new(
        0u64,
        big_lwe_sk.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );  

    // println!("Computing PBS...");
    // let start = std::time::Instant::now();
    // programmable_bootstrap_lwe_ciphertext(
    //     &ct1,
    //     &mut ct1_out,
    //     &lut1,
    //     &fourier_bsk,
    // );
    // println!("PBS took: {:?}", start.elapsed());

    println!("Computing multi bit PBS...");
    let start = std::time::Instant::now();
    multi_bit_programmable_bootstrap_lwe_ciphertext(
        &ct1,
        &mut ct1_out,
        &lut1,
        &multi_bit_bsk,
        ThreadCount(4),
        true
    );
    println!("multi bit PBS took: {:?}", start.elapsed());


    let dim_out = ct1_out.lwe_size().0;
    println!("dim out: {}", dim_out);

    let dec1: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, &ct1_out);
    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog((message_modulus.ilog2() + 1) as usize), DecompositionLevelCount(1));
    // println!("dec {:b}", dec1.0);
    // println!("scaled dec {:b}", signed_decomposer.closest_representable(dec1.0));
    let dec1: u64 =
        signed_decomposer.closest_representable(dec1.0) / delta;

    // assert_eq!(f(clear1), dec1);
    println!("dec1: {}", dec1);

    // key switch

    let mut ct1_out_small = LweCiphertext::new(
        0u64,
        small_lwe_sk.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let start = std::time::Instant::now();
    par_keyswitch_lwe_ciphertext(&ksk, &ct1_out, &mut ct1_out_small);
    println!("key switch took: {:?}", start.elapsed());

    let dec1: Plaintext<u64> = decrypt_lwe_ciphertext(&small_lwe_sk, &ct1_out_small);
    let dec1: u64 =
        signed_decomposer.closest_representable(dec1.0) / delta;    
    // assert_eq!(f(clear1), dec1);


    let mut ct1_out_big = LweCiphertext::new(
        0u64,
        big_lwe_sk.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );  

    println!("Computing multi bit PBS...");
    let start = std::time::Instant::now();
    multi_bit_programmable_bootstrap_lwe_ciphertext(
        &ct1_out_small,
        &mut ct1_out_big,
        &lut2,
        &multi_bit_bsk,
        ThreadCount(4),
        true
    );
    println!("multi bit PBS took: {:?}", start.elapsed());

    let dec1: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, &ct1_out_big);
    let dec1: u64 =
        signed_decomposer.closest_representable(dec1.0) / delta;
    println!("dec1: {}", dec1);
    assert_eq!(g(f(clear1)), dec1);



    // GPU --------------------------------
    let mut vec_cts = vec![ct1.clone()];
    let size = 128;
    for _ in 0..size{
        vec_cts.push(ct1.clone());
    }

    let mut vec_luts = vec![lut1.clone()];
    for _ in 0..size{
        vec_luts.push(lut1.clone());
    }

    // let cuda_out_cts = gpu_pbs(&streams, &bsk, &vec_cts, &vec_luts);
    let cuda_out_cts = gpu_multi_pbs(&streams, &bsk, &vec_cts, &vec_luts);

    // drop(bsk);

    // let gpu_vec_lwe_out = cuda_out_cts.to_lwe_ciphertext_list(&streams);
    // let gpu_vec_out = gpu_vec_lwe_out.chunks(vec_cts[0].lwe_size().0).map(|lwe_out| {
    //     let temp = lwe_out.into_container().to_vec();
    //     LweCiphertextOwned::from_container(temp, ciphertext_modulus)
    // }).collect::<Vec<_>>();
    
    // for ct_out in gpu_vec_out.iter(){
    //     let dec: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, ct_out);
    //     let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog((message_modulus.ilog2() + 1) as usize), DecompositionLevelCount(1));
    //     let dec: u64 =
    //         signed_decomposer.closest_representable(dec.0) / delta;
    //     assert_eq!(f(clear1), dec);
    // }



    // key switch to wopbs context ----------------

    let wopbs_parameters = LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let mut wopbs_boxed_seeder = new_seeder();
    let wopbs_seeder = wopbs_boxed_seeder.as_mut();
    let mut wopbs_secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(wopbs_seeder.seed());
    let mut wopbs_encryption_generator =
    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(wopbs_seeder.seed(), wopbs_seeder);
    println!("Generating wopbs keys right now...");

    let wopbs_small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        wopbs_parameters.lwe_dimension,
        &mut wopbs_secret_generator,
    );

    let wopbs_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        wopbs_parameters.glwe_dimension,
        wopbs_parameters.polynomial_size,
        &mut wopbs_secret_generator,
    );

    let wopbs_large_lwe_secret_key = wopbs_glwe_secret_key.clone().into_lwe_secret_key();

    let wopbs_bootstrap_key: LweBootstrapKeyOwned<u64> =
        par_allocate_and_generate_new_lwe_bootstrap_key(
            &wopbs_small_lwe_secret_key,
            &wopbs_glwe_secret_key,
            wopbs_parameters.pbs_base_log,
            wopbs_parameters.pbs_level,
            wopbs_parameters.glwe_noise_distribution,
            wopbs_parameters.ciphertext_modulus,
            &mut wopbs_encryption_generator,
        );

    let mut wopbs_small_bsk = FourierLweBootstrapKey::new(
        wopbs_bootstrap_key.input_lwe_dimension(),
        wopbs_bootstrap_key.glwe_size(),
        wopbs_bootstrap_key.polynomial_size(),
        wopbs_bootstrap_key.decomposition_base_log(),
        wopbs_bootstrap_key.decomposition_level_count(),
    );

    par_convert_standard_lwe_bootstrap_key_to_fourier(&wopbs_bootstrap_key, &mut wopbs_small_bsk);

    //KSK encryption_key -> small WoPBS key (used in the 1st KS in the extract bit)
    let ksk_wopbs_large_to_wopbs_small = allocate_and_generate_new_lwe_keyswitch_key(
        &wopbs_large_lwe_secret_key,
        &wopbs_small_lwe_secret_key,
        wopbs_parameters.ks_base_log,
        wopbs_parameters.ks_level,
        wopbs_parameters.lwe_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        &mut wopbs_encryption_generator,
    );


    // KSK to convert from input ciphertext key to the wopbs input one
    let ksk_pbs_large_to_wopbs_large = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &wopbs_large_lwe_secret_key,
        pbs_params.ks_base_log,
        pbs_params.ks_level,
        wopbs_parameters.lwe_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        &mut wopbs_encryption_generator,
    );

    // KSK large_wopbs_key -> small PBS key (used after the WoPBS computation to compute a
    // classical PBS. This allows compatibility between PBS and WoPBS
    let ksk_wopbs_large_to_pbs_small = allocate_and_generate_new_lwe_keyswitch_key(
        &wopbs_large_lwe_secret_key,
        &small_lwe_sk,
        pbs_params.ks_base_log,
        pbs_params.ks_level,
        pbs_params.lwe_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        &mut wopbs_encryption_generator,
    );

    let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &wopbs_large_lwe_secret_key,
        &wopbs_glwe_secret_key,
        wopbs_parameters.pfks_base_log,
        wopbs_parameters.pfks_level,
        wopbs_parameters.pfks_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        &mut wopbs_encryption_generator,
    );


    let mut wopbs_ct1_out = LweCiphertextOwned::new(
        0,
        ksk_pbs_large_to_wopbs_large
            .output_key_lwe_dimension()
            .to_lwe_size(),
        wopbs_parameters.ciphertext_modulus,
    );

    // Compute a key switch
    par_keyswitch_lwe_ciphertext(
        &ksk_pbs_large_to_wopbs_large,
        &ct1_out,
        &mut wopbs_ct1_out,
    );


    let dec = decrypt_lwe_ciphertext(&wopbs_large_lwe_secret_key, &wopbs_ct1_out);
    let dec: u64 =
        signed_decomposer.closest_representable(dec.0) / delta;
    println!("dec: {}", dec);

    // extract bits

    let fft = Fft::new(bsk.polynomial_size());
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();


    let delta = (1u64 << 63) / (message_modulus);
    // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
    let delta_log = DeltaLog(delta.ilog2() as usize);
    
    println!("delta log: {}", delta_log.0);

    let nb_bit_to_extract =
        f64::log2((message_modulus) as f64) as usize;
    
    println!("nb_bit_to_extract: {}", nb_bit_to_extract);


    let buffer_size_req =
     convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
         .unwrap()
         .unaligned_bytes_required();

    let buffer_size_req = buffer_size_req.max(extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
        wopbs_large_lwe_secret_key.lwe_dimension(),
        wopbs_small_lwe_secret_key.lwe_dimension(),
        wopbs_small_bsk.glwe_size(),
        wopbs_small_bsk.polynomial_size(),
        fft
    ).unwrap().unaligned_bytes_required());

    buffers.resize(buffer_size_req);

    let mut bit_extraction_output = LweCiphertextList::new(
        0u64,
        wopbs_small_lwe_secret_key.lwe_dimension().to_lwe_size(),
        LweCiphertextCount(nb_bit_to_extract),
        ciphertext_modulus,
    );

    let start = std::time::Instant::now();
    extract_bits_from_lwe_ciphertext_mem_optimized(
        &wopbs_ct1_out,
        &mut bit_extraction_output,
        &wopbs_small_bsk,
        &ksk_wopbs_large_to_wopbs_small,
        delta_log,
        ExtractedBitsCount(nb_bit_to_extract),
        fft,
        buffers.stack(),
    );
    // cpu_extract_bits(
    //     bit_extraction_output.as_mut_view(),
    //     wopbs_ct1_out.as_view(),
    //     ksk_wopbs_large_to_wopbs_small.as_view(),
    //     wopbs_small_bsk.as_view(),
    //     delta_log,
    //     ExtractedBitsCount(nb_bit_to_extract),
    //     fft,
    //     buffers.stack(),
    // );

    // gpu_extract_bits(
    //     &streams,
    //     &wopbs_bootstrap_key,
    //     bit_extraction_output.as_mut_view(),
    //     wopbs_ct1_out.as_view(),
    //     ksk_wopbs_large_to_wopbs_small.as_view(),
    //     wopbs_small_bsk.as_view(),
    //     delta_log,
    //     ExtractedBitsCount(nb_bit_to_extract),
    //     fft,
    //     buffers.stack(),
    // );
    println!("extract bits took: {:?}", start.elapsed());


    // iterate through all next
    
    let bit_modulus: u64 = 2;
    let delta = (1u64 << 63) / (bit_modulus) * 2;
    let mut vec_bits = Vec::new();
    bit_extraction_output.iter().all(|bit| {
        vec_bits.push(bit.clone());
        let dec: Plaintext<u64> = decrypt_lwe_ciphertext(&wopbs_small_lwe_secret_key, &bit);
        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog((bit_modulus.ilog2() + 1) as usize), DecompositionLevelCount(1));
        let dec: u64 =
            signed_decomposer.closest_representable(dec.0) / delta;
        println!("dec: {}", dec);
        true
    });
    println!("bits extracted ...");

    let message_bits: usize = message_modulus.ilog2() as usize;
    println!("message bits: {}", message_bits);

    let delta_log_lut = DeltaLog(64 - message_bits);

    let wopbs_polynomial_size = wopbs_parameters.polynomial_size;
    println!("wopbs_polynomial_size: {}", wopbs_polynomial_size.0);
    let poly_size = wopbs_small_bsk.polynomial_size().0;
    println!("poly size: {}", poly_size);




    // f1 is msb bit, f2 is 2nd msb bit, f3 is 3rd msb bit, f4 is lsb bit
    let f1 = |x: u64| x >> 3;
    let f2 = |x: u64| (x >> 2) & 1;
    let f3 = |x: u64| (x >> 1) & 1;
    let f4 = |x: u64| x & 1;

    let vec_functions = [f1, f2, f3, f4];

    let output_ciphertexts_count = 4;

    let lut_size = wopbs_polynomial_size.0;
    let mut lut: Vec<u64> = Vec::with_capacity(lut_size);
    for i in  0..output_ciphertexts_count{
        for j in 0..lut_size {
            let elem = vec_functions[i](j as u64 % (1 << message_bits)) << delta_log_lut.0;
            lut.push(elem);
        }
    }
    let lut_as_polynomial_list = PolynomialList::from_container(lut, wopbs_polynomial_size);

    let number_of_luts_and_output_vp_ciphertexts = LweCiphertextCount(output_ciphertexts_count);


    let vec_out_bits = cpu_cbc_vp(
        &wopbs_parameters,
        &bit_extraction_output,
        &lut_as_polynomial_list,
        &wopbs_small_bsk,
        &ksk_wopbs_large_to_pbs_small,
        &wopbs_large_lwe_secret_key,
        &cbs_pfpksk,
        wopbs_parameters.cbs_base_log,
        wopbs_parameters.cbs_level,
        &fft,
        &mut buffers,
    );

    


    





   

    // -------------------


    // testing key switching -------

    let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);

    // let wopbs_key = WopbsKey::new_wopbs_key(cks, sks, parameters)


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