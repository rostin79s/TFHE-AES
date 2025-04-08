use tfhe::shortint::ciphertext::MaxDegree;
use tfhe::shortint::parameters::Degree;
use tfhe::shortint::server_key::ManyLookupTableOwned;
use tfhe::shortint::PBSParameters;

use tfhe::core_crypto::prelude::GlweCiphertext;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::core_crypto::prelude::keyswitch_lwe_ciphertext_into_glwe_ciphertext;
use tfhe::core_crypto::prelude::ContiguousEntityContainerMut;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::core_crypto::prelude::MonomialDegree;
use tfhe::core_crypto::prelude::slice_algorithms::slice_wrapping_add_assign;
use tfhe::core_crypto::prelude::trivially_encrypt_lwe_ciphertext;
use tfhe::core_crypto::prelude::Plaintext;
use tfhe::core_crypto::prelude::LweCiphertext;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_div_assign;

use super::*;

pub fn cpu_gen_encrypted_lut
(
    params: &FHEParameters,
    pksk: &LwePackingKeyswitchKey<Vec<u64>>,
    list_cts: &LweCiphertextList<Vec<u64>>,
) -> GlweCiphertext<Vec<u64>>
{
    let (glwe_size, poly_size) = match params {
        FHEParameters::MultiBit(params) => (
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
        ),
        FHEParameters::Wopbs(params) => (
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
        ),
        FHEParameters::PBS(params) => (
            params.glwe_dimension().to_glwe_size(),
            params.polynomial_size(),
        ),
        
    };

    let cts_count = list_cts.lwe_ciphertext_count().0;
    let box_size = poly_size.0 / cts_count;
    let ciphertext_modulus = list_cts.ciphertext_modulus();
    let mut output_glwe = GlweCiphertext::new(
    0u64,
    glwe_size,
    poly_size,
    ciphertext_modulus,
    );

    let mut buffers = Vec::new();
    for ct in list_cts.iter(){
        let mut buffer = GlweCiphertext::new(
            u64::ZERO,
            output_glwe.glwe_size(),
            output_glwe.polynomial_size(),
            output_glwe.ciphertext_modulus(),
        );
        keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pksk, &ct, &mut buffer);
        buffers.push(buffer);
    }


    for degree in 0..poly_size.0 {
        let mut buffer = buffers[degree / box_size].clone();
        buffer
            .as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(degree));
            });
        slice_wrapping_add_assign(output_glwe.as_mut(), buffer.as_ref());
    }
    

    let half_box_size = box_size / 2;

    let mut body = output_glwe.get_mut_body();
    let mut poly_body = body.as_mut_polynomial();
    polynomial_wrapping_monic_monomial_div_assign(&mut poly_body, MonomialDegree(half_box_size));



    let mut mask = output_glwe.get_mut_mask();
    let mut poly_mask = mask.as_mut_polynomial_list();
    let mut poly_mask = poly_mask.get_mut(0);
    polynomial_wrapping_monic_monomial_div_assign(&mut poly_mask, MonomialDegree(half_box_size));

    return output_glwe;
}


pub fn cpu_gen_many_lut
(
    pbs_params: &FHEParameters,
    vec_functions:  Vec<impl Fn(u64) -> u64>

) -> ManyLookupTableOwned
{
    let (plaintext_modulus, polynomial_size, glwe_size, ciphertext_modulus) = match pbs_params {
        FHEParameters::MultiBit(params) => (
            params.message_modulus.0 * params.carry_modulus.0,
            params.polynomial_size,
            params.glwe_dimension.to_glwe_size(),
            params.ciphertext_modulus,
        ),
        FHEParameters::Wopbs(params) => (
            params.message_modulus.0 * params.carry_modulus.0,
            params.polynomial_size,
            params.glwe_dimension.to_glwe_size(),
            params.ciphertext_modulus,
        ),
        FHEParameters::PBS(params) => (
            params.message_modulus().0 * params.carry_modulus().0,
            params.polynomial_size(),
            params.glwe_dimension().to_glwe_size(),
            params.ciphertext_modulus(),
        ),
    };

    let delta = 
        (1_u64 << 63) / plaintext_modulus as u64;


    let mut acc = GlweCiphertext::new(
        0,
        glwe_size,
        polynomial_size,
        ciphertext_modulus,
    );

    let mut accumulator_view = acc.as_mut_view();

    accumulator_view.get_mut_mask().as_mut().fill(0);

    // Modulus of the msg contained in the msg bits and operations buffer
    let modulus_sup =  plaintext_modulus as usize;

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / modulus_sup;

    let mut body = accumulator_view.get_mut_body();
    let accumulator_u64 = body.as_mut();
    // Clear in case we don't fill the full accumulator so that the remainder part is 0
    accumulator_u64.as_mut().fill(0u64);

    let fn_counts = vec_functions.len();

    assert!(
        fn_counts <= modulus_sup / 2,
        "Cannot generate many lut accumulator for {fn_counts} functions, maximum possible is {}",
        modulus_sup / 2
    );

    // Max valid degree for a ciphertext when using the LUT we generate
    let input_max_degree = MaxDegree::new((modulus_sup / fn_counts - 1) as u64);

    let mut per_function_output_degree = vec![Degree::new(0); fn_counts];

    // If MaxDegree == 1, we can have two input values 0 and 1, so we need MaxDegree + 1 boxes
    let sample_extraction_stride = (input_max_degree.get() as usize + 1) * box_size;

    for ((function_sub_lut, output_degree), function) in accumulator_u64
        .chunks_mut(sample_extraction_stride)
        .zip(per_function_output_degree.iter_mut())
        .zip(vec_functions)
    {
        for (msg_value, sub_lut_box) in function_sub_lut.chunks_exact_mut(box_size).enumerate() {
            let msg_value = msg_value as u64;
            let function_eval = function(msg_value);
            *output_degree = Degree::new((function_eval).max(output_degree.get()));
            sub_lut_box.fill(function_eval* delta);
        }
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);

    ManyLookupTableOwned {
        acc,
        input_max_degree,
        sample_extraction_stride,
        per_function_output_degree,
    }
}

pub fn cpu_many_pbs
(
    fourier_bsk: &FourierLweBootstrapKey<ABox<[c64], ConstAlign<128>>>,
    ct: &LweCiphertext<Vec<u64>>,
    lut: &ManyLookupTableOwned,
) -> Vec<LweCiphertext<Vec<u64>>>
{
    let mut acc = lut.acc.clone();
    blind_rotate_assign(&ct, &mut acc, &fourier_bsk);

    // The accumulator has been rotated, we can now proceed with the various sample extractions
    let function_count = lut.function_count();
    let mut outputs = Vec::with_capacity(function_count);
    let ciphertext_modulus = ct.ciphertext_modulus();
    let lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

    for (fn_idx, output_degree) in lut.per_function_output_degree.iter().enumerate() {
        let monomial_degree = MonomialDegree(fn_idx * lut.sample_extraction_stride);
        let mut output_shortint_ct = LweCiphertext::new(0, lwe_size, ciphertext_modulus);

        extract_lwe_sample_from_glwe_ciphertext(
            &acc,
            &mut output_shortint_ct,
            monomial_degree,
        );
        outputs.push(output_shortint_ct);
    }

    outputs

}

pub fn cpu_gen_lut
(
    pbs_params: &FHEParameters,
    function: fn(u64) -> u64,
    padding: bool
) -> GlweCiphertext<Vec<u64>>
{
    let (plaintext_modulus, polynomial_size, glwe_dimension, ciphertext_modulus) = match pbs_params {
        FHEParameters::MultiBit(params) => (
            params.message_modulus.0 * params.carry_modulus.0,
            params.polynomial_size,
            params.glwe_dimension,
            params.ciphertext_modulus,
        ),
        FHEParameters::Wopbs(params) => (
            params.message_modulus.0 * params.carry_modulus.0,
            params.polynomial_size,
            params.glwe_dimension,
            params.ciphertext_modulus,
        ),
        FHEParameters::PBS(params) => (
            params.message_modulus().0 * params.carry_modulus().0,
            params.polynomial_size(),
            params.glwe_dimension(),
            params.ciphertext_modulus(),
        ),
    };

    let mut delta = (1_u64 << 63) / plaintext_modulus;
    if !padding{
        delta *= 2;
    }

    let lut: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        plaintext_modulus as usize,
        ciphertext_modulus,
        delta,
        function,
    );
    return lut;
}

pub fn cpu_pbs(
    fourier_bsk: &FourierLweBootstrapKey<ABox<[c64], ConstAlign<128>>>, 
    ct: &LweCiphertext<Vec<u64>>, 
    lut: &GlweCiphertext<Vec<u64>>
) -> LweCiphertext<Vec<u64>>{

    let ciphertext_modulus = ct.ciphertext_modulus();
    let lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();
    let mut ct_out = LweCiphertext::new(
        0u64,
        lwe_size,
        ciphertext_modulus,
    );  

    programmable_bootstrap_lwe_ciphertext(
        &ct,
        &mut ct_out,
        &lut,
        &fourier_bsk,
    );
    return ct_out
}

pub fn cpu_multipbs
(
    fourier_multibsk: &FourierLweMultiBitBootstrapKey<ABox<[c64], ConstAlign<128>>>, 
    ct: &LweCiphertext<Vec<u64>>, 
    lut: &GlweCiphertext<Vec<u64>>,
) -> LweCiphertext<Vec<u64>>
{
    let ciphertext_modulus = ct.ciphertext_modulus();
    let lwe_size = fourier_multibsk.output_lwe_dimension().to_lwe_size();
    let mut ct_out = LweCiphertext::new(
        0u64,
        lwe_size,
        ciphertext_modulus,
    );  

    multi_bit_programmable_bootstrap_lwe_ciphertext(
        &ct,
        &mut ct_out,
        &lut,
        &fourier_multibsk,
        ThreadCount(4),
        true
    );
    return ct_out
}

pub fn gpu_pbs(streams: &CudaStreams, bsk: &LweBootstrapKey<Vec<u64>>, vec_cts: &Vec<LweCiphertext<Vec<u64>>>, vec_luts: &Vec<GlweCiphertext<Vec<u64>>> ) -> CudaLweCiphertextList<u64>{
    let cuda_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, None, &streams);


    let gpu_index = streams.gpu_indexes[0].get();
    let ciphertext_modulus = vec_cts[0].ciphertext_modulus();
    let ciphertext_counts = vec_cts.len();
    let lwe_size = vec_cts[0].lwe_size();
    let polynomial_size = vec_luts[0].polynomial_size();

    let mut cts_container = Vec::new();
    for lwe_in in vec_cts.iter(){
        cts_container.extend(lwe_in.clone().into_container());
    }

    let cts = LweCiphertextList::from_container(cts_container, lwe_size, ciphertext_modulus);

    let cuda_cts = CudaLweCiphertextList::from_lwe_ciphertext_list(&cts, &streams);
    let mut cuda_out_cts = CudaLweCiphertextList::new(bsk.output_lwe_dimension(), LweCiphertextCount(ciphertext_counts), ciphertext_modulus, &streams);

    let mut luts_container = Vec::new();
    for lut in vec_luts.iter(){
        luts_container.extend(lut.clone().into_container());
    }

    
    let luts = GlweCiphertextList::from_container(luts_container, vec_luts[0].glwe_size(), polynomial_size, ciphertext_modulus);
    let cuda_luts = CudaGlweCiphertextList::from_glwe_ciphertext_list(&luts, &streams);

    let index_vec: Vec<u64> = (0..vec_cts.len()).map(|x| x as u64).collect::<Vec<_>>();

    let input_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };
    let output_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };
    let lut_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };

    

    let start = std::time::Instant::now();
    cuda_programmable_bootstrap_lwe_ciphertext(&cuda_cts, &mut cuda_out_cts, &cuda_luts, &lut_indexes, &output_indexes, &input_indexes, LweCiphertextCount(ciphertext_counts), &cuda_bsk, &streams);
    println!("GPU PBS took: {:?}", start.elapsed());

    return cuda_out_cts;
}

pub fn gpu_multi_pbs(streams: &CudaStreams, bsk: &LweMultiBitBootstrapKey<Vec<u64>>, vec_cts: &Vec<LweCiphertext<Vec<u64>>>, vec_luts: &Vec<GlweCiphertext<Vec<u64>>> ) -> CudaLweCiphertextList<u64>{
    let cuda_bsk = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(&bsk, &streams);

    let gpu_index = streams.gpu_indexes[0].get();
    let ciphertext_modulus = vec_cts[0].ciphertext_modulus();
    let ciphertext_counts = vec_cts.len();
    let lwe_size = vec_cts[0].lwe_size();
    let polynomial_size = vec_luts[0].polynomial_size();

    let mut cts_container = Vec::new();
    for lwe_in in vec_cts.iter(){
        cts_container.extend(lwe_in.clone().into_container());
    }

    let cts = LweCiphertextList::from_container(cts_container, lwe_size, ciphertext_modulus);

    let cuda_cts = CudaLweCiphertextList::from_lwe_ciphertext_list(&cts, &streams);
    let mut cuda_out_cts = CudaLweCiphertextList::new(bsk.output_lwe_dimension(), LweCiphertextCount(ciphertext_counts), ciphertext_modulus, &streams);

    let mut luts_container = Vec::new();
    for lut in vec_luts.iter(){
        luts_container.extend(lut.clone().into_container());
    }

    
    let luts = GlweCiphertextList::from_container(luts_container, vec_luts[0].glwe_size(), polynomial_size, ciphertext_modulus);
    let cuda_luts = CudaGlweCiphertextList::from_glwe_ciphertext_list(&luts, &streams);

    let index_vec: Vec<u64> = (0..vec_cts.len()).map(|x| x as u64).collect::<Vec<_>>();

    let input_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };
    let output_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };
    let lut_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };

    let start = std::time::Instant::now();
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(&cuda_cts, &mut cuda_out_cts, &cuda_luts, &lut_indexes, &output_indexes, &input_indexes, &cuda_bsk, &streams);
    println!("GPU multi bit PBS took: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(&cuda_cts, &mut cuda_out_cts, &cuda_luts, &lut_indexes, &output_indexes, &input_indexes, &cuda_bsk, &streams);
    println!("GPU multi bit PBS took: {:?}", start.elapsed());

    let start = std::time::Instant::now();
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(&cuda_cts, &mut cuda_out_cts, &cuda_luts, &lut_indexes, &output_indexes, &input_indexes, &cuda_bsk, &streams);
    println!("GPU multi bit PBS took: {:?}", start.elapsed());
    return cuda_out_cts;
}