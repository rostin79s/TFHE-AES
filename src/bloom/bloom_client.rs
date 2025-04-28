use tfhe::{core_crypto::prelude::{DefaultRandomGenerator, EncryptionRandomGenerator, LweCiphertext, LweSecretKey}, shortint::WopbsParameters};
use crate::gpu::{cpu_encrypt, FHEParameters};



pub fn bloom_gen_lwe
(
    wopbs_params: &WopbsParameters,
    pbs_params: &FHEParameters, 
    wopbs_encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>, 
    wopbs_small_lwe_sk: &LweSecretKey<Vec<u64>>, 
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>,
    indices: &Vec<usize>, 
    wopbs_size: usize,
    m: usize
) -> Vec<Vec<LweCiphertext<Vec<u64>>>>
{
    let plaintext_modulus: u64 = match pbs_params  {
        FHEParameters::MultiBit(params) => params.message_modulus.0 * params.carry_modulus.0,
        FHEParameters::PBS(params) => params.message_modulus.0 * params.carry_modulus.0,
        FHEParameters::Wopbs(_) => panic!("Invalid parameter: Wopbs is not supported"),
    };

    let wopbs_chunk = 1 << wopbs_size;
    
    let mut lwe_cts = Vec::new();
    for index in indices{
        let (mut q, r) = ((m-1) / wopbs_chunk, index % wopbs_chunk);
        let mut bits_r = Vec::new();
        for i in (0..wopbs_size).rev() {
            bits_r.push((r >> i) & 1);
        }
        let mut lwe_cts_index = Vec::new();
        for bit_r in bits_r{
            let lwe = cpu_encrypt(&FHEParameters::Wopbs(*wopbs_params), wopbs_encryption_generator, wopbs_small_lwe_sk, bit_r as u64, false);
            lwe_cts_index.push(lwe);
        }
        while q > 0{
            let upper = q % plaintext_modulus as usize;
            println!("upper: {}", upper);
            q = q / plaintext_modulus as usize;
            let lwe = cpu_encrypt(pbs_params, encryption_generator, small_lwe_sk, upper as u64, true);
            lwe_cts_index.push(lwe);
        }
        lwe_cts.push(lwe_cts_index);
    }
    return lwe_cts;
}