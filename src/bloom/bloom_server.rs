use core::num;
use std::cmp::{max, min};

use tfhe::integer::wopbs::{
    IntegerWopbsLUT,
    PlaintextCount, 
    CiphertextCount
};
use aligned_vec::{ABox, ConstAlign};
use tfhe::{core_crypto::prelude::{ComputationBuffers, Fft, FourierLweBootstrapKey, FourierLweMultiBitBootstrapKey, LweCiphertext, LweKeyswitchKey, LwePackingKeyswitchKey, LwePrivateFunctionalPackingKeyswitchKeyList, LweSecretKey, PolynomialList}, shortint::WopbsParameters};
use tfhe_fft::c64;

use crate::gpu::{cbs_vp::{cpu_cbs_vp, cpu_generate_lut_vp}, cpu_decrypt, cpu_lwelist_to_veclwe, cpu_veclwe_to_lwelist, key_switch::cpu_many_ksk, pbs::{cpu_gen_encrypted_lut, cpu_multipbs, cpu_pbs}, FHEParameters};



pub fn bloom_encrypted_query
(
    wopbs_big_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_small_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_params: &WopbsParameters,
    pbs_params: &FHEParameters,
    fourier_multibsk: &FourierLweMultiBitBootstrapKey<ABox<[c64], ConstAlign<128>>>,
    ksk_wopbs_large_to_pbs_small: &LweKeyswitchKey<Vec<u64>>,
    pksk: &LwePackingKeyswitchKey<Vec<u64>>,
    wopbs_fourier_bsk: &FourierLweBootstrapKey<ABox<[c64], ConstAlign<128>>>,
    cbs_pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,
    vec_vec_lwe: &Vec<Vec<LweCiphertext<Vec<u64>>>>,
    wopbs_size: usize,
    bloom: &Vec<u64>,
) -> Vec<LweCiphertext<Vec<u64>>>
{
    let plaintext_modulus: usize = match pbs_params {
        FHEParameters::MultiBit(params) => (params.message_modulus.0 * params.carry_modulus.0) as usize,
        FHEParameters::PBS(params) => (params.message_modulus.0 * params.carry_modulus.0) as usize,
        FHEParameters::Wopbs(_) => panic!("Invalid parameter: Wopbs is not supported"),
    };
    let m = bloom.len();
    let wopbs_chunk = 1 << wopbs_size;
    let number_of_functions = (m-1) / wopbs_chunk + 1;
    println!("number_of_functions: {}", number_of_functions);
    let output_count = number_of_functions;

    let mut vec_functions = Vec::new();
    for i in 0..number_of_functions{
        let start = i * wopbs_chunk;
        let end = min(m, (i + 1) * wopbs_chunk);
        println!("start: {}, end: {}", start, end);
        let sub_bloom = &bloom[start..end];
        let f = |x: u64| sub_bloom[(x % sub_bloom.len() as u64) as usize];
        vec_functions.push(f);
    }

    let lut_size = max(wopbs_fourier_bsk.polynomial_size().0, 1 << wopbs_size);
    let mut containers = Vec::new();
    for function in vec_functions{
        let mut lut: Vec<u64> = Vec::with_capacity(lut_size);
        for i in 0..lut_size {
            lut.push((function(i as u64 % (1 << wopbs_size))) << 62);
        }
        containers.extend(lut);
    }
    let vp_lut = PolynomialList::from_container(containers, wopbs_params.polynomial_size);

    
    let mut vec_lwe_out = Vec::new();
    for vec_lwe in vec_vec_lwe{

        // get first wopbs_size elements of vec_lwe
        let vec_lwe_wopbs: Vec<_> = vec_lwe.iter().take(wopbs_size).cloned().collect();
        let vec_lwe_pbs: Vec<_> = vec_lwe.iter().skip(wopbs_size).cloned().collect();



        let list_bits = cpu_veclwe_to_lwelist(&vec_lwe_wopbs);

        let fft = Fft::new(wopbs_fourier_bsk.polynomial_size());
        let fft = fft.as_view();
        let mut buffers = ComputationBuffers::new();
        let list_bits_out = cpu_cbs_vp(&wopbs_params, &list_bits, &vp_lut, output_count, wopbs_fourier_bsk, cbs_pfpksk, &fft, &mut buffers, wopbs_big_lwe_sk, wopbs_small_lwe_sk);
        let mut vec_bits_out = cpu_lwelist_to_veclwe(&list_bits_out);
        for bit_out in vec_bits_out.clone(){
            let dec = cpu_decrypt(&FHEParameters::Wopbs(*wopbs_params), wopbs_big_lwe_sk, &bit_out, true);
            println!("dec: {}", dec);
        }

        if vec_lwe_pbs.len() > 0{
            vec_bits_out = cpu_many_ksk(ksk_wopbs_large_to_pbs_small, &vec_bits_out);
        }


        // level 1
        
        
        // split vec bits out into chunks of plaintext_modulus
        for lwe_pbs in vec_lwe_pbs{
            println!("-1");
            let mut vec_temp_bits = Vec::new();
            for vec_bits_out_chunk in vec_bits_out.chunks(plaintext_modulus){
                let list_bits_out_chunk = cpu_veclwe_to_lwelist(&vec_bits_out_chunk.to_vec());
                let glwe_ct = cpu_gen_encrypted_lut(pbs_params, pksk, &list_bits_out_chunk);
                let lwe = cpu_multipbs(fourier_multibsk, &lwe_pbs, &glwe_ct);
                vec_temp_bits.push(lwe);
            }
            vec_bits_out = vec_temp_bits;
        }
        // assert_eq!(vec_bits_out.len(), 1);
        vec_lwe_out.push(vec_bits_out[0].clone());
    }
    return vec_lwe_out;
}
