mod gpu;
mod server;
mod bloom;
mod tables;

use bloom::{bloom::*, bloom_client::bloom_gen_lwe, bloom_server::bloom_encrypted_query};
use gpu::{
    cbs_vp::*, cpu_decrypt, cpu_encrypt, cpu_gen_bsk, cpu_gen_ksk, cpu_gen_multibsk, cpu_gen_pksk, cpu_gen_wopbs_keys, cpu_lwelist_to_veclwe, cpu_params, cpu_seed, cpu_veclwe_to_lwelist, extract_bits::*, key_switch::*, pbs::*, pbsmany::{cpu_gen_pbsmany_lut, cpu_pbsmany}, FHEParameters
};
use tfhe::{core_crypto::{gpu::{vec::GpuIndex, CudaStreams}, prelude::{allocate_and_generate_new_lwe_keyswitch_key, ComputationBuffers, Fft}}, shortint::parameters::{v0_11::multi_bit::gaussian::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, v1_0::V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64}};



fn example(){
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let pbs_params = V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    

    let (mut boxed_seeder, mut encryption_generator, small_lwe_sk, glwe_sk, big_lwe_sk ) = cpu_seed(&FHEParameters::MultiBit(pbs_params));
    let ksk = cpu_gen_ksk(&pbs_params, &mut encryption_generator, &small_lwe_sk, &big_lwe_sk);
    let (bsk, fourier_bsk) = cpu_gen_bsk(&FHEParameters::MultiBit(pbs_params), &mut boxed_seeder, &small_lwe_sk, &glwe_sk);
    let (multibsk, fourier_multibsk) = cpu_gen_multibsk(&pbs_params, &mut encryption_generator, &small_lwe_sk, &glwe_sk);
    let pksk = cpu_gen_pksk(&pbs_params, &small_lwe_sk, &glwe_sk, &mut encryption_generator);
    

    let clear1 = 11;
    let ct1 = cpu_encrypt(&FHEParameters::MultiBit(pbs_params), &mut encryption_generator, &small_lwe_sk, clear1, true);

    // let f1 = |x: u64| x;
    // let lut1 = cpu_gen_lut(&FHEParameters::MultiBit(pbs_params), f1, true);
    // let ct1_out = cpu_multipbs(&fourier_multibsk, &ct1, &lut1);
    // let ct1_out = cpu_ksk(&ksk, &ct1_out);


    // // apply many lut


    let f1 = |x: u64| x;
    let f2 = |x: u64| x+1;
    let f3 = |x: u64| x+2;
    let f4 = |x: u64| x+3;
    let vec_functions = vec![f1, f2, f3, f4];
    // let many_lut = cpu_gen_many_lut(&FHEParameters::MultiBit(pbs_params), vec_functions.clone());
    // let cts = cpu_many_pbs(&fourier_bsk, &ct1, &many_lut);

    // for ct in cts.iter(){
    //     let dec = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &big_lwe_sk, &ct, true);
    //     println!("many lut dec: {}", dec);
    // }


    // apply gen pbs
    let (mut lut, v) = cpu_gen_pbsmany_lut(&FHEParameters::MultiBit(pbs_params), vec_functions);
    let ctsag = cpu_pbsmany(&fourier_bsk.as_view(), &ct1, &mut lut, v);

    for ct in ctsag.iter(){
        let dec = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &big_lwe_sk, &ct, true);
        println!("PBSmany lut dec: {}", dec);
    }
    // packing key switch

    // let cts_count = 16;
    // let f2 = |x: u64| x;
    // let mut vec_cts = Vec::new();
    // for i in 0..cts_count{
    //     let clear = (f2(i)) % cts_count;
    //     let ct = cpu_encrypt(&FHEParameters::MultiBit(pbs_params), &mut encryption_generator, &small_lwe_sk, clear, true);
    //     let ct = cpu_multipbs(&fourier_multibsk, &ct, &lut1);
    //     let ct = cpu_ksk(&ksk, &ct);
    //     // let mut ct = LweCiphertext::new(0u64, pbs_params.lwe_dimension.to_lwe_size(), pbs_params.ciphertext_modulus);
    //     // let plaintext = Plaintext((i << 59) as u64);
    //     // trivially_encrypt_lwe_ciphertext(&mut ct, plaintext);
    //     vec_cts.push(ct);
    // }
    // let list_cts = cpu_veclwe_to_lwelist(&vec_cts);


    // let start = std::time::Instant::now();

    // let glwe_ct = cpu_gen_encrypted_lut(&FHEParameters::MultiBit(pbs_params), &pksk, &list_cts);

    // println!("packing key switch took: {:?}", start.elapsed());

    // let enc_lut_size = glwe_ct.clone().into_container().len();
    // println!("enc_lut_size: {}", enc_lut_size);

    // let ct1_out = cpu_multipbs(&fourier_multibsk, &ct1_out, &glwe_ct);
    // let dec1 = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &big_lwe_sk, &ct1_out, true);
    // println!("dec1 large: {}", dec1);
    // assert_eq!(dec1, f2(clear1));

    // // let ct1_out = cpu_ksk(&ksk, &ct1_out);
    // // let ct1_out = cpu_multipbs(&big_lwe_sk, &fourier_multibsk, &ct1_out, &lut1);


    // // extract bits on normal pbs
    // println!("extracting bits on normal pbs");

    // let fft = Fft::new(bsk.polynomial_size());
    // let fft = fft.as_view();
    // let mut buffers = ComputationBuffers::new();

    // let pbs_bits1 = cpu_eb(&FHEParameters::MultiBit(pbs_params), &small_lwe_sk, &big_lwe_sk, &ksk, &fourier_bsk, &ct1_out, &mut buffers, &fft, true);
    // // let pbs_bits2 = pbs_bits1.clone();
    // // let pbs_bits3 = pbs_bits1.clone();
    // // let pbs_bits4 = pbs_bits1.clone();
    // // let pbs_bits5 = pbs_bits1.clone();

    // let mut vec_pbs_bits = cpu_lwelist_to_veclwe(&pbs_bits1);
    // // vec_pbs_bits.extend(cpu_lwelist_to_veclwe(&pbs_bits1));
    // // vec_pbs_bits.extend(cpu_lwelist_to_veclwe(&pbs_bits1));
    // // vec_pbs_bits.extend(cpu_lwelist_to_veclwe(&pbs_bits1));
    // // vec_pbs_bits.extend(cpu_lwelist_to_veclwe(&pbs_bits1));
    // // vec_pbs_bits.extend(cpu_lwelist_to_veclwe(&pbs_bits1));
    // // vec_pbs_bits.extend(cpu_lwelist_to_veclwe(&pbs_bits1));





    // // key switch to wopbs context ---------------------------------------------


    // let wopbs_params = cpu_params();
    // // let wopbs_params = LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    // let (mut wopbs_boxed_seeder, mut wopbs_encryption_generator, wopbs_small_lwe_sk, wopbs_glwe_secret_key, wopbs_big_lwe_sk) =  cpu_seed(&FHEParameters::Wopbs(wopbs_params));
    // let (wopbs_bsk, wopbs_fourier_bsk) = cpu_gen_bsk(&FHEParameters::Wopbs(wopbs_params), &mut wopbs_boxed_seeder, &wopbs_small_lwe_sk, &wopbs_glwe_secret_key);
    // let (ksk_wopbs_large_to_wopbs_small, ksk_pbs_large_to_wopbs_large, ksk_wopbs_large_to_pbs_small, cbs_pfpksk) = cpu_gen_wopbs_keys(&pbs_params, &small_lwe_sk, &big_lwe_sk, &wopbs_params, &mut wopbs_encryption_generator, &wopbs_small_lwe_sk, &wopbs_big_lwe_sk, &wopbs_glwe_secret_key);


    // let ksk_pbs_small_to_wopbs_small = allocate_and_generate_new_lwe_keyswitch_key(
    //     &small_lwe_sk, 
    //     &wopbs_small_lwe_sk, 
    //     wopbs_params.ks_base_log, 
    //     wopbs_params.ks_level, 
    //     wopbs_params.lwe_noise_distribution, 
    //     wopbs_params.ciphertext_modulus, 
    //     &mut wopbs_encryption_generator
    // );
    // let ksk_pbs_large_to_wopbs_small = allocate_and_generate_new_lwe_keyswitch_key(
    //     &big_lwe_sk, 
    //     &wopbs_small_lwe_sk, 
    //     wopbs_params.ks_base_log, 
    //     wopbs_params.ks_level, 
    //     wopbs_params.lwe_noise_distribution, 
    //     wopbs_params.ciphertext_modulus, 
    //     &mut wopbs_encryption_generator
    // );


    // let mut vec_wopbs_bits = Vec::new();
    // let mut integer = 0;
    // for (index, pbs_bit) in vec_pbs_bits.iter().enumerate(){
    //     let pbs_bit_switched = cpu_ksk(&ksk_pbs_small_to_wopbs_small, &pbs_bit);
    //     let wopbs_dec = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_small_lwe_sk, &pbs_bit_switched, false);
    //     integer += wopbs_dec << (vec_pbs_bits.len() - index - 1);
    //     vec_wopbs_bits.push(pbs_bit_switched);
    // }
    // println!("integer: {}", integer);
    // let wopbs_bits = cpu_veclwe_to_lwelist(&vec_wopbs_bits);


    // let vec_wopbs_bits = cpu_many_ksk(&ksk_pbs_large_to_wopbs_small, &cts);
    // let wopbs_bits = cpu_veclwe_to_lwelist(&vec_wopbs_bits);
    // for wopbs_bit in vec_wopbs_bits.iter(){
    //     let dec: u64 = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_small_lwe_sk, &wopbs_bit, false);
    //     println!("many dec in wopbs: {}", dec);
    // }



    // // // circuit bootstrapping *********************************************************************************************************************************************************************************************************************************************

    // let fft = Fft::new(wopbs_bsk.polynomial_size());
    // let fft = fft.as_view();
    // let mut buffers = ComputationBuffers::new();



    // let output_count = wopbs_bits.lwe_ciphertext_count().0;

    // let f1: fn(u64) -> u64 = |x: u64| x;
    // let mut vec_functions = Vec::new();
    // vec_functions.push(f1);
    // let lut = cpu_generate_lut_vp(&wopbs_params, &vec_functions, output_count, false);

    
    // let cont = lut.clone().into_container();
    // // println!("cont: {:?}", cont);
    // let cont_size = cont.len();
    // println!("cont size: {}", cont_size);
    // let poly_count = lut.polynomial_count().0;
    // println!("poly_count: {}", poly_count);
    
    // let lut_size = lut.polynomial_size();
    // println!("lut_size: {}", lut_size.0);


    
    // let out_bits_list = cpu_cbs_vp(
    //     &wopbs_params,
    //     &wopbs_bits,
    //     &lut,
    //     output_count,
    //     &wopbs_fourier_bsk,
    //     &cbs_pfpksk,
    //     &fft,
    //     &mut buffers,
    //     &wopbs_big_lwe_sk,
    //     &wopbs_small_lwe_sk
    // );

    // let vec_out_bits = cpu_lwelist_to_veclwe(&out_bits_list);



    // let mut out_integer = 0;
    // for (index, bit_out) in vec_out_bits.iter().enumerate(){
    //     let dec: u64 = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_big_lwe_sk, &bit_out, false);
    //     println!("cbs dec: {}", dec);
    //     out_integer += dec << (vec_out_bits.len() - index - 1);
    // }

    // println!("out_integer: {}", out_integer);
    // assert_eq!(out_integer, f1(integer));


    // let vec_out_bits = cpu_many_ksk(&ksk_wopbs_large_to_wopbs_small, &vec_out_bits);
    // let new_bits = cpu_veclwe_to_lwelist(&vec_out_bits);

    // let lut = cpu_generate_lut_vp(&wopbs_params, &vec_functions, output_count, false);

    // let out_bits_list = cpu_cbs_vp(
    //     &wopbs_params,
    //     &new_bits,
    //     &lut,
    //     &wopbs_fourier_bsk,
    //     &wopbs_big_lwe_sk,
    //     &cbs_pfpksk,
    //     &fft,
    //     &mut buffers,
    // );

    // let vec_out_bits = cpu_lwelist_to_veclwe(&out_bits_list);
    // for bit_out in vec_out_bits.iter(){
    //     let dec: u64 = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_big_lwe_sk, &bit_out, false);
    //     println!("dec: {}", dec);
    // }



    // let fft = Fft::new(wopbs_bsk.polynomial_size());
    // let fft = fft.as_view();
    // let mut buffers = ComputationBuffers::new();


    // let start = std::time::Instant::now();
    // let bit = cpu_eb(&FHEParameters::Wopbs(wopbs_params), &wopbs_small_lwe_sk, &wopbs_big_lwe_sk, &ksk_wopbs_large_to_wopbs_small, &wopbs_fourier_bsk, &vec_out_bits[0], &mut buffers, &fft, false);
    // println!("CPU extract bits took: {:?}", start.elapsed());

    // let g = |x: u64| x;
    // let lut2 = cpu_gen_lut(&FHEParameters::Wopbs(wopbs_params), g, true);

    // let mut bit = cpu_ksk(&ksk_wopbs_large_to_wopbs_small, &vec_out_bits[0]);
    // let bit_clone = bit.clone();
    // // lwe_ciphertext_add_assign(&mut bit, &bit_clone);
    // // lwe_ciphertext_add_assign(&mut bit, &bit_clone);
    // let mut bit = cpu_pbs(&wopbs_big_lwe_sk, &wopbs_fourier_bsk, &bit, &lut2);


    // let mut bit = cpu_ksk(&ksk_wopbs_large_to_wopbs_small, &bit);
    // // lwe_ciphertext_add_assign(&mut bit, &bit_clone);
    // // let mut bit = cpu_pbs(&wopbs_big_lwe_sk, &wopbs_fourier_bsk, &bit, &lut2);

    // // let mut bit = cpu_ksk(&ksk_wopbs_large_to_wopbs_small, &bit);
    // // lwe_ciphertext_add_assign(&mut bit, &bit_clone);
    // // let mut bit = cpu_pbs(&wopbs_big_lwe_sk, &wopbs_fourier_bsk, &bit, &lut2);

    // let dec = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_small_lwe_sk, &bit, false);
    // assert_eq!(dec, 3);
    // println!("bit bootstrapped: {}", dec);

    

    


    // let new_bits = cpu_veclwe_to_lwelist(&vec_out_bits);

    // let vec_out_bits = cpu_cbs_vp(
    //     &wopbs_params,
    //     &new_bits,
    //     &lut,
    //     &wopbs_fourier_bsk,
    //     &ksk_wopbs_large_to_wopbs_small,
    //     &wopbs_big_lwe_sk,
    //     &cbs_pfpksk,
    //     &fft,
    //     &mut buffers,
    // );



    // GPU --------------------------------


    // let mut vec_cts = vec![ct1.clone()];
    // let size = 10000;
    // for _ in 0..size{
    //     vec_cts.push(ct1.clone());
    // }

    // let mut vec_luts = vec![lut1.clone()];
    // for _ in 0..size{
    //     vec_luts.push(lut1.clone());
    // }

    // // let cuda_out_cts = gpu_pbs(&streams, &bsk, &vec_cts, &vec_luts);
    // let cuda_out_cts = gpu_multi_pbs(&streams, &multibsk, &vec_cts, &vec_luts);


    // let ciphertext_modulus = pbs_params.ciphertext_modulus;
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

    // let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);

    // // let wopbs_key = WopbsKey::new_wopbs_key(cks, sks, parameters)


    // let ksk = sks.key_switching_key;
    // let ct1= cks.encrypt(2).ct;
    // let ct2 = cks.encrypt(3).ct;
    // let ct3 = cks.encrypt(1).ct;
    // let vec_lwe_in = vec![ct1, ct2, ct3];

    // let start = std::time::Instant::now();
    // let cuda_vec_lwe_out = gpu_key_switch(&streams, &ksk, &vec_lwe_in);
    // println!("GPU key switch took: {:?}", start.elapsed());
    // let gpu_vec_lwe_out = cuda_vec_lwe_out.to_lwe_ciphertext_list(&streams);
    // let gpu_vec_out = gpu_vec_lwe_out.into_container();

    // let start = std::time::Instant::now();
    // let vec_lwe_out = cpu_many_ksk(&ksk, &vec_lwe_in);
    // println!("CPU key switch took: {:?}", start.elapsed());
    // let mut vec_out = Vec::new();
    // for lwe_out in vec_lwe_out.iter(){
    //     vec_out.extend(lwe_out.clone().into_container());
    // }
    // assert_eq!(vec_out, gpu_vec_out);


    

 
}


fn bloom(){
    let prob_failure = 1e-1; // False positive rate
    let db_size = 2_usize.pow(3); // 2^20 database size

    let (m, h) = bloom_params(prob_failure, db_size);
    println!("Computed Bloom Filter Size (m): {}", m);
    println!("Computed Number of Hash Functions (h): {}", h);

    let m = 1 << 8;

    let (hash_seeds, bloom_filter, values) = bloom_create(m, h, db_size);
    println!("Generated {} hash functions and created Bloom filter of size {}", hash_seeds.len(), bloom_filter.len());

    let value = values[0];
    let indices = bloom_query(value, &hash_seeds, m);
    println!("indices {:?}", indices);


    let pbs_params = V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

    let (mut boxed_seeder, mut encryption_generator, small_lwe_sk, glwe_sk, big_lwe_sk ) = cpu_seed(&FHEParameters::MultiBit(pbs_params));
    let ksk = cpu_gen_ksk(&pbs_params, &mut encryption_generator, &small_lwe_sk, &big_lwe_sk);
    let (bsk, fourier_bsk) = cpu_gen_bsk(&FHEParameters::MultiBit(pbs_params), &mut boxed_seeder, &small_lwe_sk, &glwe_sk);
    let (multibsk, fourier_multibsk) = cpu_gen_multibsk(&pbs_params, &mut encryption_generator, &small_lwe_sk, &glwe_sk);
    let pksk = cpu_gen_pksk(&pbs_params, &small_lwe_sk, &glwe_sk, &mut encryption_generator);



    let wopbs_params = cpu_params();
    let (mut wopbs_boxed_seeder, mut wopbs_encryption_generator, wopbs_small_lwe_sk, wopbs_glwe_secret_key, wopbs_big_lwe_sk) =  cpu_seed(&FHEParameters::Wopbs(wopbs_params));
    let (wopbs_bsk, wopbs_fourier_bsk) = cpu_gen_bsk(&FHEParameters::Wopbs(wopbs_params), &mut wopbs_boxed_seeder, &wopbs_small_lwe_sk, &wopbs_glwe_secret_key);
    let (ksk_wopbs_large_to_wopbs_small, ksk_pbs_large_to_wopbs_large, ksk_wopbs_large_to_pbs_small, cbs_pfpksk) = cpu_gen_wopbs_keys(&pbs_params, &small_lwe_sk, &big_lwe_sk, &wopbs_params, &mut wopbs_encryption_generator, &wopbs_small_lwe_sk, &wopbs_big_lwe_sk, &wopbs_glwe_secret_key);


    let wopbs_size = 4;
    
    let vec_lwe = bloom_gen_lwe(&wopbs_params, &FHEParameters::MultiBit(pbs_params), &mut wopbs_encryption_generator, &wopbs_small_lwe_sk, &mut encryption_generator, &small_lwe_sk, &indices, wopbs_size, m);
    
    
    let vec_lwe_out = bloom_encrypted_query(&wopbs_big_lwe_sk, &wopbs_small_lwe_sk, &wopbs_params, &FHEParameters::MultiBit(pbs_params), &fourier_multibsk, &ksk_wopbs_large_to_pbs_small, &pksk, &wopbs_fourier_bsk, &cbs_pfpksk, &vec_lwe, wopbs_size, &bloom_filter);
    
    
    for (index, lwe) in vec_lwe_out.iter().enumerate(){
        let dec: u64;
        if m > (1 << wopbs_size){
            dec = cpu_decrypt(&FHEParameters::MultiBit(pbs_params), &big_lwe_sk, &lwe, true);
        }
        else{
            dec = cpu_decrypt(&FHEParameters::Wopbs(wopbs_params), &wopbs_big_lwe_sk, &lwe, true);
        }
        println!("index and bit: {} and {}", index, dec);
    }



}


fn main() {
    loop{
        example();
        break;
    }

    // bloom();
}