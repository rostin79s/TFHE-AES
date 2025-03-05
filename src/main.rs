mod gpu;
mod server;
pub mod tables;
use server::sbox::gen_lut::gen_lut;

use gpu::{
    cbs_vp::*, cpu_decrypt, cpu_encrypt, cpu_gen_bsk, cpu_gen_ksk, cpu_gen_multibsk, cpu_gen_wopbs_keys, cpu_lwelist_to_veclwe, cpu_params, cpu_seed, cpu_veclwe_to_lwelist, extract_bits::*, key_switch::*, pbs::*, FHEParameters
};
use tfhe::{core_crypto::{gpu::{vec::GpuIndex, CudaStreams}, prelude::{allocate_and_generate_new_lwe_keyswitch_key, par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list, ComputationBuffers, Fft}}, integer::wopbs, shortint::{gen_keys, parameters::{LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64}}};
use tfhe::core_crypto::prelude::par_allocate_and_generate_new_lwe_bootstrap_key;



fn example(){
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    let pbs_params = PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    

    let (mut boxed_seeder, mut encryption_generator, small_lwe_sk, glwe_sk, big_lwe_sk ) = cpu_seed(&FHEParameters::MultiBit(pbs_params));
    let ksk = cpu_gen_ksk(&pbs_params, &mut encryption_generator, &small_lwe_sk, &big_lwe_sk);
    let (bsk, fourier_bsk) = cpu_gen_bsk(&FHEParameters::MultiBit(pbs_params), &mut boxed_seeder, &small_lwe_sk, &glwe_sk);
    let (multibsk, fourier_multibsk) = cpu_gen_multibsk(&pbs_params, &mut encryption_generator, &small_lwe_sk, &glwe_sk);
    

    let clear1 = 11;
    let ct1 = cpu_encrypt(&pbs_params, &mut encryption_generator, &small_lwe_sk, clear1);

    let clear2 = 5u64;
    let ct2 = cpu_encrypt(&pbs_params, &mut encryption_generator, &small_lwe_sk, clear2);

    let clear3 = 7u64;
    let ct3 = cpu_encrypt(&pbs_params, &mut encryption_generator, &small_lwe_sk, clear3);



    let f1 = |x: u64| x;
    let lut1 = cpu_gen_lut(&pbs_params, f1, true);

    let f2 = |x: u64| x + 3;
    let lut2 = cpu_gen_lut(&pbs_params, f2, true);

    let f3 = |x: u64| x + 1;
    let lut3 = cpu_gen_lut(&pbs_params, f3, true);


    // let ct1_out = cpu_pbs(&pbs_params, &fourier_bsk, &ct1, &lut1);

    let ct1_out = cpu_multipbs(&pbs_params, &big_lwe_sk, &fourier_multibsk, &ct1, &lut1);


   

    let dec1 = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &big_lwe_sk, &ct1_out, true);
    println!("dec1 large: {}", dec1);
    
    let ct1_switched = cpu_ksk(&ksk, &ct1_out);

    let dec1 = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &small_lwe_sk, &ct1_switched, true);
    println!("dec1 small: {}", dec1);



    let ct1_out = cpu_multipbs(&pbs_params, &big_lwe_sk, &fourier_multibsk, &ct1_switched, &lut1);

    let dec1 = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &big_lwe_sk, &ct1_out, true);


    // extract bits on normal pbs
    println!("extracting bits on normal pbs");

    let fft = Fft::new(bsk.polynomial_size());
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();

    let pbs_bits = cpu_eb(&FHEParameters::MultiBit(pbs_params), &small_lwe_sk, &big_lwe_sk, &ksk, &fourier_bsk, &ct1_out, &mut buffers, &fft);



    // key switch to wopbs context ---------------------------------------------


    let wopbs_params = cpu_params();
    // let wopbs_params = LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let (mut wopbs_boxed_seeder, mut wopbs_encryption_generator, wopbs_small_lwe_secret_key, wopbs_glwe_secret_key, wopbs_big_lwe_secret_key) =  cpu_seed(&FHEParameters::Wopbs(wopbs_params));
    let (wopbs_bsk, wopbs_fourier_bsk) = cpu_gen_bsk(&FHEParameters::Wopbs(wopbs_params), &mut wopbs_boxed_seeder, &wopbs_small_lwe_secret_key, &wopbs_glwe_secret_key);
    let (ksk_wopbs_large_to_wopbs_small, ksk_pbs_large_to_wopbs_large, ksk_wopbs_large_to_pbs_small, cbs_pfpksk) = cpu_gen_wopbs_keys(&pbs_params, &small_lwe_sk, &big_lwe_sk, &wopbs_params, &mut wopbs_encryption_generator, &wopbs_small_lwe_secret_key, &wopbs_big_lwe_secret_key, &wopbs_glwe_secret_key);


    let ksk_pbs_small_to_wopbs_small = allocate_and_generate_new_lwe_keyswitch_key(
        &small_lwe_sk, 
        &wopbs_small_lwe_secret_key, 
        wopbs_params.ks_base_log, 
        wopbs_params.ks_level, 
        wopbs_params.lwe_noise_distribution, 
        wopbs_params.ciphertext_modulus, 
        &mut wopbs_encryption_generator
    );

    let sizein = ksk_pbs_small_to_wopbs_small.input_key_lwe_dimension().0;
    let sizeout = ksk_pbs_small_to_wopbs_small.output_key_lwe_dimension().0;
    println!("sizein: {}", sizein);
    println!("sizeout: {}", sizeout);
    

    let vec_pbs_bits = cpu_lwelist_to_veclwe(&pbs_bits);
    let n = vec_pbs_bits[0].lwe_size().0;
    println!("n: {}", n);
    let mut vec_wopbs_bits = Vec::new();
    for pbs_bit in vec_pbs_bits.iter(){
        let pbs_bit_switched = cpu_ksk(&ksk_pbs_small_to_wopbs_small, &pbs_bit);
        let wopbs_dec = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_small_lwe_secret_key, &pbs_bit_switched, false);
        println!("wopbs dec: {}", wopbs_dec);
        vec_wopbs_bits.push(pbs_bit_switched);
    }

    let wopbs_bits = cpu_veclwe_to_lwelist(&vec_wopbs_bits);


    // circuit bootstrapping

    let fft = Fft::new(wopbs_bsk.polynomial_size());
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();




    // let bits = cpu_eb(&FHEParameters::Wopbs(wopbs_params), &wopbs_small_lwe_secret_key, &wopbs_big_lwe_secret_key, &ksk_wopbs_large_to_wopbs_small, &wopbs_fourier_bsk, &wopbs_ct1_out, &mut buffers, &fft);


    let f1: fn(u64) -> u64 = |x: u64| x + 1;
    let f2 = |x: u64| x + 3;
    let mut vec_functions = Vec::new();
    vec_functions.push(f1);
    vec_functions.push(f2);
    let output_count = wopbs_bits.lwe_ciphertext_count().0;
    let lut = cpu_generate_lut_vp(&wopbs_params, &vec_functions, output_count);
    

    let out_bits_list = cpu_cbs_vp(
        &wopbs_params,
        &wopbs_bits,
        &lut,
        &wopbs_fourier_bsk,
        &wopbs_big_lwe_secret_key,
        &cbs_pfpksk,
        &fft,
        &mut buffers,
    );

    let vec_out_bits = cpu_lwelist_to_veclwe(&out_bits_list);
    let vec_out_bits = cpu_many_ksk(&ksk_wopbs_large_to_wopbs_small, &vec_out_bits);

    let count = wopbs_bits.lwe_ciphertext_count().0;
    let mut index = count - 1;
    let mut integer = 0;
    let mut j = 0;
    for bit_out in vec_out_bits.iter(){
        let dec: u64 = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_small_lwe_secret_key, &bit_out, false);
        integer += dec << index;
        if index == 0{
            println!("f{}: {}", j, integer);
            assert_eq!(integer, vec_functions[j](clear1));
            integer = 0;
            index = count;
            j += 1;
        }
        index -= 1;
        
    }

    let new_bits = cpu_veclwe_to_lwelist(&vec_out_bits[0..output_count].to_vec());

    let new_out_bits = cpu_cbs_vp(
        &wopbs_params,
        &new_bits,
        &lut,
        &wopbs_fourier_bsk,
        &wopbs_big_lwe_secret_key,
        &cbs_pfpksk,
        &fft,
        &mut buffers,
    );

    let vec_new_out_bits = cpu_lwelist_to_veclwe(&new_out_bits);
    let vec_pbs_bits = cpu_many_ksk(&ksk_wopbs_large_to_pbs_small, &vec_new_out_bits);

    for pbs_bit in vec_pbs_bits.iter(){
        // let function = |x: u64| x;
        // let lut = &cpu_gen_lut(&pbs_params, function, true);
        // let new_pbs_bit = cpu_multipbs(&pbs_params, &big_lwe_sk, &fourier_multibsk, pbs_bit, lut);
        // let new_pbs_bit = cpu_ksk(&ksk, &new_pbs_bit);

        let dec: u64 = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &small_lwe_sk, &pbs_bit, true);
        println!("dec: {}", dec);
    }

    

    

    


    // let new_bits = cpu_veclwe_to_lwelist(&vec_out_bits);

    // let vec_out_bits = cpu_cbs_vp(
    //     &wopbs_params,
    //     &new_bits,
    //     &lut,
    //     &wopbs_fourier_bsk,
    //     &ksk_wopbs_large_to_wopbs_small,
    //     &wopbs_big_lwe_secret_key,
    //     &cbs_pfpksk,
    //     &fft,
    //     &mut buffers,
    // );



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
    let cuda_out_cts = gpu_multi_pbs(&streams, &multibsk, &vec_cts, &vec_luts);

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

    // testing key switching -------

    let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);

    // let wopbs_key = WopbsKey::new_wopbs_key(cks, sks, parameters)


    let ksk = sks.key_switching_key;
    let ct1= cks.encrypt(2).ct;
    let ct2 = cks.encrypt(3).ct;
    let ct3 = cks.encrypt(1).ct;
    let vec_lwe_in = vec![ct1, ct2, ct3];

    let start = std::time::Instant::now();
    let cuda_vec_lwe_out = gpu_key_switch(&streams, &ksk, &vec_lwe_in);
    println!("GPU key switch took: {:?}", start.elapsed());
    let gpu_vec_lwe_out = cuda_vec_lwe_out.to_lwe_ciphertext_list(&streams);
    let gpu_vec_out = gpu_vec_lwe_out.into_container();

    let start = std::time::Instant::now();
    let vec_lwe_out = cpu_many_ksk(&ksk, &vec_lwe_in);
    println!("CPU key switch took: {:?}", start.elapsed());
    let mut vec_out = Vec::new();
    for lwe_out in vec_lwe_out.iter(){
        vec_out.extend(lwe_out.clone().into_container());
    }
    assert_eq!(vec_out, gpu_vec_out);


    

 
}

// Main function to run the FHE AES CTR encryption. All functions, AES key expansion, encryption and decryption are run single threaded. Only CTR is parallelized.
fn main() {
    example();
}