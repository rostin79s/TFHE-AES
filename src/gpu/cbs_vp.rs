use tfhe::shortint::WopbsParameters;
use super::*;

pub fn cpu_cbs_vp<
    BskCont
>
(
    wopbs_parameters: &WopbsParameters,
    bits: &LweCiphertextList<Vec<u64>>,
    lut: &PolynomialList<Vec<u64>>,
    wopbs_small_bsk: &FourierLweBootstrapKey<BskCont>,
    wopbs_large_lwe_secret_key: &LweSecretKey<Vec<u64>>,
    cbs_pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,
    fft: &FftView<'_>,
    buffers: &mut ComputationBuffers,
) -> LweCiphertextList<Vec<u64>>
where 
    BskCont: Container<Element = c64>,
{
    let ciphertext_modulus = bits.ciphertext_modulus();
    let poly_size = wopbs_parameters.polynomial_size;
    let output_ciphertexts_count = lut.polynomial_count().0;
    let number_of_luts_and_output_vp_ciphertexts = LweCiphertextCount(output_ciphertexts_count);
    let nb_bit_to_extract = bits.lwe_ciphertext_count().0;

    let mut output_cbs_vp = LweCiphertextList::new(
        0u64,
        wopbs_large_lwe_secret_key.lwe_dimension().to_lwe_size(),
        number_of_luts_and_output_vp_ciphertexts,
        ciphertext_modulus,
    );

    println!("Computing circuit bootstrap...");
    println!("lwe dimension: {}", wopbs_parameters.lwe_dimension.0);
    let buffer_size_req = 
    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<
        u64,
    >(
        LweCiphertextCount(nb_bit_to_extract),
        number_of_luts_and_output_vp_ciphertexts,
        LweSize(wopbs_parameters.lwe_dimension.0),
        PolynomialCount(output_ciphertexts_count),
        wopbs_small_bsk.output_lwe_dimension().to_lwe_size(),
        wopbs_small_bsk.glwe_size(),
        poly_size,
        wopbs_parameters.cbs_level,
        *fft,
    )
    .unwrap()
    .unaligned_bytes_required();


    buffers.resize(buffer_size_req);

    let start = std::time::Instant::now();
    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
    &bits,
    &mut output_cbs_vp,
    &lut,
    &wopbs_small_bsk,
    &cbs_pfpksk,
    wopbs_parameters.cbs_base_log,
    wopbs_parameters.cbs_level,
    *fft,
    buffers.stack(),
    );
    println!("circuit_bootstrap_boolean_vertical_packing took: {:?}", start.elapsed());
    
    return output_cbs_vp;
}


pub fn cpu_generate_lut_vp(
    wopbs_params: &WopbsParameters,
    vec_functions: &Vec<fn(u64) -> u64>,
    output_count: usize,

) -> PolynomialList<Vec<u64>>
{

    let mut containers = Vec::new();
    for function in vec_functions{
        let mut integer_lut = gen_lut_vp(
            wopbs_params.message_modulus.0 as usize, 
            wopbs_params.carry_modulus.0 as usize, wopbs_params.polynomial_size.0, output_count, function);
    
        let sag = integer_lut.as_mut().lut();
        let asb = sag.as_polynomial().into_container().to_vec();
        containers.extend(asb);
    }

    let lut = PolynomialList::from_container(containers, wopbs_params.polynomial_size);
    return lut;
}


use tfhe::integer::wopbs::{
    IntegerWopbsLUT,
    PlaintextCount, 
    CiphertextCount
};

// This is the function wopbs_key.generate_radix_lut_without_padding(...), except the last part of the function had
// a bug that assumed there is carry, and I fixed it for my use case and use this function instead.
pub fn gen_lut_vp<F>(message_mod: usize, carry_mod: usize, poly_size: usize, nb_block: usize, f: F) -> IntegerWopbsLUT 
    where
        F: Fn(u64) -> u64
    {
        let log_message_modulus =
            f64::log2((message_mod) as f64) as u64;
        let log_carry_modulus = f64::log2((carry_mod) as f64) as u64;
        let log_basis = log_message_modulus + log_carry_modulus;
        let delta = 64 - log_basis;
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
                let masked_value = (f(value as u64) >> (log_message_modulus * rev_block_index as u64))
                    % (1 << log_message_modulus); 
                lut[block_index][index] = masked_value << delta; 
            }
        }
        lut
    }
