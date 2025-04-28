use dyn_stack::PodStack;
use tfhe::shortint::WopbsParameters;
use tfhe::core_crypto::commons::math::decomposition::DecompositionLevel;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::homomorphic_shift_boolean;
use aligned_vec::CACHELINE_ALIGN;
use tfhe_fft::c64;
use super::*;

pub fn cpu_circuit_bootstrap_boolean(
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    lwe_in: LweCiphertext<&[u64]>,
    mut ggsw_out: GgswCiphertext<&mut [u64]>,
    delta_log: DeltaLog,
    pfpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[u64]>,
    fft: FftView<'_>,
    stack: &mut PodStack,
    wopbs_big_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_small_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_params: &WopbsParameters,
) {
    let level_cbs = ggsw_out.decomposition_level_count();
    let base_log_cbs = ggsw_out.decomposition_base_log();
    let fourier_bsk_output_lwe_dimension = fourier_bsk.output_lwe_dimension();

    // Output for every bootstrapping
    let (lwe_out_bs_buffer_data, stack) = stack.make_aligned_with(
        fourier_bsk_output_lwe_dimension.to_lwe_size().0,
        CACHELINE_ALIGN,
        |_| u64::ZERO,
    );
    let mut lwe_out_bs_buffer: LweCiphertext<Vec<u64>> =
        LweCiphertext::from_container((&mut *lwe_out_bs_buffer_data).to_vec(), lwe_in.ciphertext_modulus());

    for (output_index, mut ggsw_level_matrix) in ggsw_out.iter_mut().enumerate() {
        let decomposition_level = DecompositionLevel(level_cbs.0 - output_index);

        let start = std::time::Instant::now();
        println!("decomposition_level: {:?}", decomposition_level);
        homomorphic_shift_boolean(
            fourier_bsk,
            lwe_out_bs_buffer.as_mut_view(),
            lwe_in.as_view(),
            decomposition_level,
            base_log_cbs,
            delta_log,
            fft,
            stack,
        );
        // let dec = cpu_decrypt_delta(wopbs_params, big_lwe_sk, ct, delta);
        println!("homomorphic_shift_boolean: {:?}", start.elapsed());   

        for (pfpksk, mut glwe_out) in pfpksk_list
            .iter()
            .zip(ggsw_level_matrix.as_mut_glwe_list().iter_mut())
        {
            let start = std::time::Instant::now();
            private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                &pfpksk,
                &mut glwe_out,
                &lwe_out_bs_buffer,
            );
            println!("private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext: {:?}", start.elapsed());
        }
    }
}

pub fn cpu_circuit_bootstrap_boolean_vertical_packing
(
    big_lut_as_polynomial_list: &PolynomialList<Vec<u64>>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    lwe_list_out: &mut LweCiphertextList<Vec<u64>>,
    lwe_list_in: &LweCiphertextList<Vec<u64>>,
    pfpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: &mut PodStack,
    wopbs_big_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_small_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_params: &WopbsParameters,
) 
{

    let glwe_size = pfpksk_list.output_key_glwe_dimension().to_glwe_size();
    let (ggsw_list_data, stack) = stack.make_aligned_with(
        lwe_list_in.lwe_ciphertext_count().0 * pfpksk_list.output_polynomial_size().0 / 2
            * glwe_size.0
            * glwe_size.0
            * level_cbs.0,
        CACHELINE_ALIGN,
        |_| c64::default(),
    );

    let (ggsw_res_data, stack) = stack.make_aligned_with(
        pfpksk_list.output_polynomial_size().0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
        CACHELINE_ALIGN,
        |_| u64::ZERO,
    );

    let mut ggsw_list = FourierGgswCiphertextListMutView::new(
        ggsw_list_data,
        lwe_list_in.lwe_ciphertext_count().0,
        glwe_size,
        pfpksk_list.output_polynomial_size(),
        base_log_cbs,
        level_cbs,
    );

    let mut ggsw_res = GgswCiphertext::from_container(
        ggsw_res_data,
        glwe_size,
        pfpksk_list.output_polynomial_size(),
        base_log_cbs,
        pfpksk_list.ciphertext_modulus(),
    );

    let start = std::time::Instant::now();

    for (lwe_in, ggsw) in izip!(lwe_list_in.iter(), ggsw_list.as_mut_view().into_ggsw_iter()) {
        cpu_circuit_bootstrap_boolean(
            fourier_bsk,
            lwe_in,
            ggsw_res.as_mut_view(),
            DeltaLog((u64::BITS - 1).try_into().unwrap()),
            pfpksk_list.as_view(),
            fft,
            stack,
            wopbs_big_lwe_sk,
            wopbs_small_lwe_sk,
            wopbs_params,
        );

        ggsw.fill_with_forward_fourier(ggsw_res.as_view(), fft, stack);
    }

    println!("circuit_bootstrap_boolean: {:?}", start.elapsed());


    let number_of_luts = lwe_list_out.lwe_ciphertext_count().0;

    let small_lut_size = big_lut_as_polynomial_list.polynomial_count().0 / number_of_luts;


    let start = std::time::Instant::now();
    for (lut, lwe_out) in izip!(
        big_lut_as_polynomial_list.chunks_exact(small_lut_size),
        lwe_list_out.iter_mut(),
    ) {
        let start = std::time::Instant::now();
        vertical_packing(lut, lwe_out, ggsw_list.as_view(), fft, stack);
        println!("vertical_packing: {:?}", start.elapsed());
        // break;
    }

    println!("vertical_packing total: {:?}", start.elapsed());



}

pub fn cpu_cbs_vp<
    BskCont
>
(
    wopbs_parameters: &WopbsParameters,
    bits: &LweCiphertextList<Vec<u64>>,
    lut: &PolynomialList<Vec<u64>>,
    output_count: usize,
    wopbs_small_bsk: &FourierLweBootstrapKey<BskCont>,
    cbs_pfpksk: &LwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,
    fft: &FftView<'_>,
    buffers: &mut ComputationBuffers,
    wopbs_big_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_small_lwe_sk: &LweSecretKey<Vec<u64>>,
) -> LweCiphertextList<Vec<u64>>
where 
    BskCont: Container<Element = c64>,
{
    let ciphertext_modulus = bits.ciphertext_modulus();
    let poly_size = wopbs_parameters.polynomial_size; 
    let nb_bit_to_extract = bits.lwe_ciphertext_count().0;
    let lut_count = lut.polynomial_count().0;
    let lwe_size = wopbs_small_bsk.output_lwe_dimension().to_lwe_size();
    let number_of_luts_and_output_vp_ciphertexts = LweCiphertextCount(output_count);

    let mut output_cbs_vp = LweCiphertextList::new(
        0u64,
        lwe_size,
        number_of_luts_and_output_vp_ciphertexts,
        ciphertext_modulus,
    );

    let buffer_size_req = 
    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<
        u64,
    >(
        LweCiphertextCount(nb_bit_to_extract),
        number_of_luts_and_output_vp_ciphertexts,
        LweSize(wopbs_parameters.lwe_dimension.0),
        PolynomialCount(lut_count),
        wopbs_small_bsk.output_lwe_dimension().to_lwe_size(),
        wopbs_small_bsk.glwe_size(),
        poly_size,
        wopbs_parameters.cbs_level,
        *fft,
    )
    .unwrap()
    .unaligned_bytes_required();


    buffers.resize(buffer_size_req * 2);

    cpu_circuit_bootstrap_boolean_vertical_packing(
        lut,
        wopbs_small_bsk.as_view(),
        &mut output_cbs_vp,
        &bits,
        &cbs_pfpksk,
        wopbs_parameters.cbs_level,
        wopbs_parameters.cbs_base_log,
        *fft,
        buffers.stack(),
        wopbs_big_lwe_sk,
        wopbs_small_lwe_sk,
        wopbs_parameters,
        );
    
    return output_cbs_vp;
}


pub fn cpu_generate_lut_vp(
    wopbs_params: &WopbsParameters,
    vec_functions: &Vec<impl Fn(u64) -> u64>,
    output_count: usize,
    padding: bool

) -> PolynomialList<Vec<u64>>
{

    let mut containers = Vec::new();
    for function in vec_functions{
        let mut integer_lut = gen_lut_vp(
            wopbs_params.message_modulus.0 as usize, 
            wopbs_params.carry_modulus.0 as usize, wopbs_params.polynomial_size.0, output_count, function, padding);
    
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
pub fn gen_lut_vp<F>(message_mod: usize, carry_mod: usize, poly_size: usize, nb_block: usize, f: F, padding: bool) -> IntegerWopbsLUT 
    where
        F: Fn(u64) -> u64
    {
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
                let masked_value = (f(value as u64) >> (log_message_modulus * rev_block_index as u64))
                    % (1 << log_message_modulus); 
                lut[block_index][index] = masked_value << delta; 
            }
        }
        lut
}
