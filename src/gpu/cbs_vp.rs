
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
    ksk_wopbs_large_to_wopbs_small: &LweKeyswitchKey<Vec<u64>>,
    wopbs_large_lwe_secret_key: &LweSecretKey<Vec<u64>>,
    cbs_pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,
    fft: &FftView<'_>,
    buffers: &mut ComputationBuffers,
) -> Vec<LweCiphertext<Vec<u64>>>
where 
    BskCont: Container<Element = c64>,
{
    let ciphertext_modulus = bits.ciphertext_modulus();
    let poly_size = wopbs_parameters.polynomial_size.0;
    let lut_size = lut.polynomial_count().0;
    let output_ciphertexts_count = lut_size;
    let number_of_luts_and_output_vp_ciphertexts = LweCiphertextCount(output_ciphertexts_count);
    let nb_bit_to_extract = ((wopbs_parameters.message_modulus.0 * wopbs_parameters.carry_modulus.0)) as usize;
    let wopbs_polynomial_size = PolynomialSize(poly_size);

    let mut output_cbs_vp = LweCiphertextList::new(
        0u64,
        wopbs_large_lwe_secret_key.lwe_dimension().to_lwe_size(),
        number_of_luts_and_output_vp_ciphertexts,
        ciphertext_modulus,
    );

    println!("Computing circuit bootstrap...");
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
        wopbs_polynomial_size,
        wopbs_parameters.cbs_level,
        *fft,
    )
    .unwrap()
    .unaligned_bytes_required();

    println!("buffer size req: {}", buffer_size_req);

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

    let size = output_cbs_vp.lwe_ciphertext_count().0;

    let bit_modulus: u64 = 2;
    let delta = (1u64 << 63) / (bit_modulus) * 2;
    let mut vec_out_bits = Vec::new();
    output_cbs_vp.iter().all(|bit| {
        
        let dec: Plaintext<u64> = decrypt_lwe_ciphertext(&wopbs_large_lwe_secret_key, &bit);
        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog((bit_modulus.ilog2()) as usize), DecompositionLevelCount(1));
        let dec: u64 =
            signed_decomposer.closest_representable(dec.0) / delta;
        println!("dec: {}", dec);
        
        let mut switched_bit = LweCiphertext::new(0, ksk_wopbs_large_to_wopbs_small.output_lwe_size(), ciphertext_modulus);
        keyswitch_lwe_ciphertext(&ksk_wopbs_large_to_wopbs_small, &bit, &mut switched_bit);
        vec_out_bits.push(switched_bit.clone());
        true
    });
    return vec_out_bits;
}


pub fn generate_lut_vp(
    wopbs_parameters: &WopbsParameters,
    vec_functions: &Vec<fn(u64) -> u64>,

) -> PolynomialList<Vec<u64>>
{
    let plaintext_modulus = wopbs_parameters.message_modulus.0 * wopbs_parameters.carry_modulus.0;
    let message_bits: usize = plaintext_modulus.ilog2() as usize;
    println!("message_bits: {}", message_bits);
    let delta_log_lut = DeltaLog(64 - message_bits);
    let poly_size = wopbs_parameters.polynomial_size;

    let f1: Box<dyn Fn(u64) -> u64> = Box::new(|x: u64| (x >> 3) << (message_bits - 1));
    let f2: Box<dyn Fn(u64) -> u64> = Box::new(|x: u64| ((x >> 2) & 1) << (message_bits - 1));
    let f3: Box<dyn Fn(u64) -> u64> = Box::new(|x: u64| ((x >> 1) & 1) << (message_bits - 1));
    let f4: Box<dyn Fn(u64) -> u64> = Box::new(|x: u64| (x & 1) << (message_bits - 1));
    let vec_subfunctions = vec![f1, f2, f3, f4];


    let output_ciphertexts_count = vec_functions.len() * 4;

    let lut_size = poly_size.0;
    let mut lut: Vec<u64> = Vec::with_capacity(lut_size);
    for i in  0..output_ciphertexts_count{
        for j in 0..lut_size {
            let elem = vec_subfunctions[i%4](vec_functions[i/4](j as u64 % (1 << message_bits))) << delta_log_lut.0;
            lut.push(elem);
        }
    }
    let lut_as_polynomial_list = PolynomialList::from_container(lut, poly_size);
    return lut_as_polynomial_list;

}