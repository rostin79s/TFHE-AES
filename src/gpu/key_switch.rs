use tfhe::{
    shortint::{
        prelude::{
            LweDimension
        }
    },
    core_crypto::{
        prelude::{
            LweKeyswitchKey,
            LweCiphertext,
            LweCiphertextList,
            LweSize,
            LweCiphertextCount,
            keyswitch_lwe_ciphertext
        },
        gpu::{
            CudaStreams,
            vec::{
                CudaVec,
                GpuIndex
            },
            lwe_ciphertext_list::CudaLweCiphertextList,
            lwe_keyswitch_key::CudaLweKeyswitchKey,
            cuda_keyswitch_lwe_ciphertext,

        },
    }
};


pub fn gpu_key_switch(streams: &CudaStreams, ksk: &LweKeyswitchKey<Vec<u64>>, vec_lwe_in: &Vec<LweCiphertext<Vec<u64>>>) -> CudaLweCiphertextList<u64>{
    let gpu_index = streams.gpu_indexes[0].0;
    let cuda_ksk = CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk, &streams);

    let lwe_size = vec_lwe_in[0].lwe_size();
    println!("lwe_size: {}", lwe_size.0);
    let ciphertext_modulus = vec_lwe_in[0].ciphertext_modulus();

    let mut cts_container = Vec::new();
    for lwe_in in vec_lwe_in.iter(){
        cts_container.extend(lwe_in.clone().into_container());
    }

    let cts = LweCiphertextList::from_container(cts_container, lwe_size, ciphertext_modulus);

    let out_lwe_size = ksk.output_key_lwe_dimension();
    println!("out_lwe_size: {}", out_lwe_size.0);
    let ciphertext_counts = vec_lwe_in.len();
    
    let cuda_cts = CudaLweCiphertextList::from_lwe_ciphertext_list(&cts, &streams);
    let mut cuda_out_cts = CudaLweCiphertextList::new(out_lwe_size, LweCiphertextCount(ciphertext_counts), ciphertext_modulus, &streams);


    // index_vec should be from 0 to len vec_lwe_in - 1
    let index_vec: Vec<u64> = (0..vec_lwe_in.len()).map(|x| x as u64).collect::<Vec<_>>();

    let input_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };
    let output_indexes = unsafe { CudaVec::from_cpu_async(&index_vec, &streams, gpu_index) };

    let start = std::time::Instant::now();
    cuda_keyswitch_lwe_ciphertext(&cuda_ksk, &cuda_cts, &mut cuda_out_cts, &input_indexes, &output_indexes, &streams);
    println!("cuda_keyswitch_lwe_ciphertext took: {:?}", start.elapsed());
    return cuda_out_cts;
}

pub fn cpu_key_switch(ksk: &LweKeyswitchKey<Vec<u64>>, vec_lwe_in: &Vec<LweCiphertext<Vec<u64>>>) -> Vec<LweCiphertext<Vec<u64>>>{
    let lwe_size = ksk.output_lwe_size();
    let ciphertext_modulus = vec_lwe_in[0].ciphertext_modulus();
    let mut vec_lwe_out = Vec::new();
    for lwe_in in vec_lwe_in.iter(){
        let mut lwe_out = LweCiphertext::new(0, lwe_size, ciphertext_modulus);
        keyswitch_lwe_ciphertext(&ksk, &lwe_in, &mut lwe_out);
        vec_lwe_out.push(lwe_out);
    }
    return vec_lwe_out;

    
}