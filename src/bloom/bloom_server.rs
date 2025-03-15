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

use crate::gpu::{cbs_vp::{cpu_cbs_vp, cpu_generate_lut_vp}, cpu_decrypt, cpu_lwelist_to_veclwe, cpu_veclwe_to_lwelist, pbs::{cpu_gen_encrypted_lut, cpu_multipbs, cpu_pbs}, FHEParameters};



pub fn bloom_encrypted_query
(
    wopbs_big_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_params: &WopbsParameters,
    pbs_params: &FHEParameters,
    fourier_multibsk: &FourierLweMultiBitBootstrapKey<ABox<[c64], ConstAlign<128>>>,
    ksk: &LweKeyswitchKey<Vec<u64>>,
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
        FHEParameters::PBS(params) => (params.message_modulus().0 * params.carry_modulus().0) as usize,
        FHEParameters::Wopbs(_) => panic!("Invalid parameter: Wopbs is not supported"),
    };
    let output_count = 1;

    let m = bloom.len();
    let wopbs_chunk = 1 << wopbs_size;
    let number_of_functions = m / wopbs_chunk + 1;

    let mut vec_functions = Vec::new();
    for i in 0..number_of_functions{
        let start = i * wopbs_chunk;
        let end = min(m, (i + 1) * wopbs_chunk);
        println!("start: {}, end: {}", start, end);
        let sub_bloom = &bloom[start..end];
        let f = |x: u64| sub_bloom[(x % sub_bloom.len() as u64) as usize];
        // vec_functions.push(bloom);
        vec_functions.push(f);
    }

    // let mut containers = Vec::new();
    // for function in vec_functions{
    //     let mut integer_lut = bloom_lut_vp(
    //         wopbs_params.message_modulus.0 as usize, 
    //         wopbs_params.carry_modulus.0 as usize, wopbs_params.polynomial_size.0, 1, bloom, true);
    
    //     let sag = integer_lut.as_mut().lut();
    //     let asb = sag.as_polynomial().into_container().to_vec();
    //     containers.extend(asb);
    // }
    // let vp_lut = PolynomialList::from_container(containers, wopbs_params.polynomial_size);

    let lut_size = max(wopbs_fourier_bsk.polynomial_size().0, 1 << wopbs_size);

    let mut lut: Vec<u64> = Vec::with_capacity(lut_size);

    for i in 0..lut_size {
        lut.push((vec_functions[0](i as u64 % (1 << wopbs_size))) << 62);
    }
    let vp_lut = PolynomialList::from_container(lut, wopbs_fourier_bsk.polynomial_size());

    // let vp_lut = cpu_generate_lut_vp(wopbs_params, &vec_functions, output_count, true);
    
    let mut vec_lwe_out = Vec::new();
    for vec_lwe in vec_vec_lwe{

        // get first wopbs_size elements of vec_lwe
        let vec_lwe_wopbs: Vec<_> = vec_lwe.iter().take(wopbs_size).cloned().collect();
        let vec_lwe_pbs: Vec<_> = vec_lwe.iter().skip(wopbs_size).cloned().collect();



        let list_bits = cpu_veclwe_to_lwelist(&vec_lwe_wopbs);

        let fft = Fft::new(wopbs_fourier_bsk.polynomial_size());
        let fft = fft.as_view();
        let mut buffers = ComputationBuffers::new();
        let list_bits_out = cpu_cbs_vp(&wopbs_params, &list_bits, &vp_lut, output_count, wopbs_fourier_bsk, cbs_pfpksk, &fft, &mut buffers);
        let mut vec_bits_out = cpu_lwelist_to_veclwe(&list_bits_out);
        for bit_out in &mut vec_bits_out{
            let dec = cpu_decrypt(&FHEParameters::Wopbs(*wopbs_params), wopbs_big_lwe_sk, bit_out, true);
            println!("dec: {}", dec);
        }
        println!("\n");


        // level 1
        
        
        // split vec bits out into chunks of plaintext_modulus
        for lwe_pbs in vec_lwe_pbs{
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



// This is the function wopbs_key.generate_radix_lut_without_padding(...), except the last part of the function had
// a bug that assumed there is carry, and I fixed it for my use case and use this function instead.
pub fn bloom_lut_vp(message_mod: usize, carry_mod: usize, poly_size: usize, nb_block: usize, f: &[u64], padding: bool) -> IntegerWopbsLUT{
        let log_message_modulus =
            f64::log2((message_mod) as f64) as u64;
        let log_carry_modulus = f64::log2((carry_mod) as f64) as u64;
        let log_basis = log_message_modulus + log_carry_modulus;
        let delta = if padding {
            64 - log_basis - 1
        } else {
            64 - log_basis
        };
        let poly_size = poly_size;
        let mut lut_size = 1 << (nb_block * log_basis as usize);
        if lut_size < poly_size {
            lut_size = poly_size;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(nb_block));

        for index in 0..lut_size {
            let mut value = 0;
            let mut tmp_index = index;
            for i in 0..nb_block as u64 {
                let tmp = tmp_index % (1 << log_basis);
                tmp_index >>= log_basis;
                value += tmp << (log_message_modulus * i);
            }

            for block_index in 0..nb_block {
                let rev_block_index = nb_block - 1 - block_index;
                let masked_value = (f[value as usize] % 2) >> (log_message_modulus * rev_block_index as u64)
                    % (1 << log_message_modulus); 
                lut[block_index][index] = masked_value << delta; 
            }
        }
        lut
}
