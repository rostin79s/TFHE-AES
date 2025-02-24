use tfhe::core_crypto::commons::ciphertext_modulus;
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
use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;

pub fn gpu_pbs(streams: &CudaStreams, bsk: &LweBootstrapKey<Vec<u64>>, vec_cts: &Vec<LweCiphertext<Vec<u64>>>, vec_luts: &Vec<GlweCiphertext<Vec<u64>>> ) -> CudaLweCiphertextList<u64>{
    let cuda_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, &streams);


    let gpu_index = streams.gpu_indexes[0].0;
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

    let gpu_index = streams.gpu_indexes[0].0;
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
    return cuda_out_cts;
}