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
use tfhe::core_crypto::commons::math::random::BoundedDistribution;
use tfhe::core_crypto::gpu::cuda_keyswitch_lwe_ciphertext;
use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use tfhe::core_crypto::prelude::{LweCiphertextCount, LweCiphertextList, LweSize};
use tfhe::integer::backward_compatibility::ciphertext;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::parameters::{LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_3_KS_PBS, LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS, PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64};
use tfhe::shortint::Ciphertext;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;

use dyn_stack::PodStack;
use aligned_vec::CACHELINE_ALIGN;

pub fn cpu_extract_bits<Scalar: UnsignedTorus + CastInto<usize>>(
    mut lwe_list_out: LweCiphertextList<&'_ mut [Scalar]>,
    lwe_in: LweCiphertext<&'_ [Scalar]>,
    ksk: LweKeyswitchKey<&'_ [Scalar]>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    delta_log: DeltaLog,
    number_of_bits_to_extract: ExtractedBitsCount,
    fft: FftView<'_>,
    stack: &mut PodStack,
) {
    debug_assert!(lwe_list_out.ciphertext_modulus() == lwe_in.ciphertext_modulus());
    debug_assert!(lwe_in.ciphertext_modulus() == ksk.ciphertext_modulus());
    debug_assert!(
        ksk.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    let ciphertext_n_bits = Scalar::BITS;
    let number_of_bits_to_extract = number_of_bits_to_extract.0;

    debug_assert!(
        ciphertext_n_bits >= number_of_bits_to_extract + delta_log.0,
        "Tried to extract {} bits, while the maximum number of extractable bits for {} bits
        ciphertexts and a scaling factor of 2^{} is {}",
        number_of_bits_to_extract,
        ciphertext_n_bits,
        delta_log.0,
        ciphertext_n_bits - delta_log.0,
    );
    debug_assert!(
        lwe_list_out.lwe_size().to_lwe_dimension() == ksk.output_key_lwe_dimension(),
        "lwe_list_out needs to have an lwe_size of {}, got {}",
        ksk.output_key_lwe_dimension().0,
        lwe_list_out.lwe_size().to_lwe_dimension().0,
    );
    debug_assert!(
        lwe_list_out.lwe_ciphertext_count().0 == number_of_bits_to_extract,
        "lwe_list_out needs to have a ciphertext count of {}, got {}",
        number_of_bits_to_extract,
        lwe_list_out.lwe_ciphertext_count().0,
    );
    debug_assert!(
        lwe_in.lwe_size() == fourier_bsk.output_lwe_dimension().to_lwe_size(),
        "lwe_in needs to have an LWE dimension of {}, got {}",
        fourier_bsk.output_lwe_dimension().to_lwe_size().0,
        lwe_in.lwe_size().0,
    );
    debug_assert!(
        ksk.output_key_lwe_dimension() == fourier_bsk.input_lwe_dimension(),
        "ksk needs to have an output LWE dimension of {}, got {}",
        fourier_bsk.input_lwe_dimension().0,
        ksk.output_key_lwe_dimension().0,
    );
    debug_assert!(lwe_list_out.ciphertext_modulus() == lwe_in.ciphertext_modulus());
    debug_assert!(lwe_in.ciphertext_modulus() == ksk.ciphertext_modulus());

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();
    let ciphertext_modulus = lwe_in.ciphertext_modulus();

    let align = CACHELINE_ALIGN;

    let (lwe_in_buffer_data, stack) = stack.collect_aligned(align, lwe_in.as_ref().iter().copied());
    let mut lwe_in_buffer =
        LweCiphertext::from_container(&mut *lwe_in_buffer_data, lwe_in.ciphertext_modulus());

    let (lwe_out_ks_buffer_data, stack) =
        stack.make_aligned_with(ksk.output_lwe_size().0, align, |_| Scalar::ZERO);
    let mut lwe_out_ks_buffer =
        LweCiphertext::from_container(&mut *lwe_out_ks_buffer_data, ksk.ciphertext_modulus());

    let (pbs_accumulator_data, stack) =
        stack.make_aligned_with(glwe_size.0 * polynomial_size.0, align, |_| Scalar::ZERO);
    let mut pbs_accumulator = GlweCiphertextMutView::from_container(
        &mut *pbs_accumulator_data,
        polynomial_size,
        ciphertext_modulus,
    );

    let lwe_size = glwe_dimension
        .to_equivalent_lwe_dimension(polynomial_size)
        .to_lwe_size();
    let (lwe_out_pbs_buffer_data, stack) =
        stack.make_aligned_with(lwe_size.0, align, |_| Scalar::ZERO);
    let mut lwe_out_pbs_buffer = LweCiphertext::from_container(
        &mut *lwe_out_pbs_buffer_data,
        lwe_list_out.ciphertext_modulus(),
    );

    // We iterate on the list in reverse as we want to store the extracted MSB at index 0
    for (bit_idx, mut output_ct) in lwe_list_out.iter_mut().rev().enumerate() {
        // Block to keep the lwe_bit_left_shift_buffer_data alive only as long as needed
        {
            // Shift on padding bit
            let (lwe_bit_left_shift_buffer_data, _) = stack.collect_aligned(
                align,
                lwe_in_buffer
                    .as_ref()
                    .iter()
                    .map(|s| *s << (ciphertext_n_bits - delta_log.0 - bit_idx - 1)),
            );

            // Key switch to input PBS key
            keyswitch_lwe_ciphertext(
                &ksk,
                &LweCiphertext::from_container(
                    lwe_bit_left_shift_buffer_data,
                    lwe_in.ciphertext_modulus(),
                ),
                &mut lwe_out_ks_buffer,
            );
        }

        // Store the keyswitch output unmodified to the output list (as we need to to do other
        // computations on the output of the keyswitch)
        output_ct
            .as_mut()
            .copy_from_slice(lwe_out_ks_buffer.as_ref());

        // If this was the last extracted bit, break
        // we subtract 1 because if the number_of_bits_to_extract is 1 we want to stop right away
        if bit_idx == number_of_bits_to_extract - 1 {
            break;
        }

        // Add q/4 to center the error while computing a negacyclic LUT
        let out_ks_body = lwe_out_ks_buffer.get_mut_body().data;
        *out_ks_body = (*out_ks_body).wrapping_add(Scalar::ONE << (ciphertext_n_bits - 2));

        // Fill lut for the current bit (equivalent to trivial encryption as mask is 0s)
        // The LUT is filled with -alpha in each coefficient where alpha = delta*2^{bit_idx-1}
        for poly_coeff in &mut pbs_accumulator
            .as_mut_view()
            .get_mut_body()
            .as_mut_polynomial()
            .iter_mut()
        {
            *poly_coeff = Scalar::ZERO.wrapping_sub(Scalar::ONE << (delta_log.0 - 1 + bit_idx));
        }

        println!("Computing PBS...");
        let start = std::time::Instant::now();
        programmable_bootstrap_lwe_ciphertext(
            &lwe_out_ks_buffer,
            &mut lwe_out_pbs_buffer,
            &pbs_accumulator,
            &fourier_bsk,
        );
        println!("PBS took: {:?}", start.elapsed());

        // fourier_bsk.bootstrap(
        //     lwe_out_pbs_buffer.as_mut_view(),
        //     lwe_out_ks_buffer.as_view(),
        //     pbs_accumulator.as_view(),
        //     fft,
        //     stack,
        // );

        // Add alpha where alpha = delta*2^{bit_idx-1} to end up with an encryption of 0 if the
        // extracted bit was 0 and 1 in the other case
        let out_pbs_body = lwe_out_pbs_buffer.get_mut_body().data;

        *out_pbs_body = (*out_pbs_body).wrapping_add(Scalar::ONE << (delta_log.0 + bit_idx - 1));

        // Remove the extracted bit from the initial LWE to get a 0 at the extracted bit location.
        izip!(lwe_in_buffer.as_mut(), lwe_out_pbs_buffer.as_ref())
            .for_each(|(out, inp)| *out = (*out).wrapping_sub(*inp));
    }
}


pub fn gpu_extract_bits(
    streams: &CudaStreams,
    bsk: &LweBootstrapKey<Vec<u64>>,
    mut lwe_list_out: LweCiphertextList<&'_ mut [u64]>,
    lwe_in: LweCiphertext<&'_ [u64]>,
    ksk: LweKeyswitchKey<&'_ [u64]>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    delta_log: DeltaLog,
    number_of_bits_to_extract: ExtractedBitsCount,
    fft: FftView<'_>,
    stack: &mut PodStack,
) {
    debug_assert!(lwe_list_out.ciphertext_modulus() == lwe_in.ciphertext_modulus());
    debug_assert!(lwe_in.ciphertext_modulus() == ksk.ciphertext_modulus());
    debug_assert!(
        ksk.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    let ciphertext_n_bits = u64::BITS;
    let number_of_bits_to_extract = number_of_bits_to_extract.0;

    debug_assert!(
        ciphertext_n_bits >= (number_of_bits_to_extract + delta_log.0).try_into().unwrap(),
        "Tried to extract {} bits, while the maximum number of extractable bits for {} bits
        ciphertexts and a scaling factor of 2^{} is {}",
        number_of_bits_to_extract,
        ciphertext_n_bits,
        delta_log.0,
        ciphertext_n_bits - delta_log.0 as u32,
    );
    debug_assert!(
        lwe_list_out.lwe_size().to_lwe_dimension() == ksk.output_key_lwe_dimension(),
        "lwe_list_out needs to have an lwe_size of {}, got {}",
        ksk.output_key_lwe_dimension().0,
        lwe_list_out.lwe_size().to_lwe_dimension().0,
    );
    debug_assert!(
        lwe_list_out.lwe_ciphertext_count().0 == number_of_bits_to_extract,
        "lwe_list_out needs to have a ciphertext count of {}, got {}",
        number_of_bits_to_extract,
        lwe_list_out.lwe_ciphertext_count().0,
    );
    debug_assert!(
        lwe_in.lwe_size() == fourier_bsk.output_lwe_dimension().to_lwe_size(),
        "lwe_in needs to have an LWE dimension of {}, got {}",
        fourier_bsk.output_lwe_dimension().to_lwe_size().0,
        lwe_in.lwe_size().0,
    );
    debug_assert!(
        ksk.output_key_lwe_dimension() == fourier_bsk.input_lwe_dimension(),
        "ksk needs to have an output LWE dimension of {}, got {}",
        fourier_bsk.input_lwe_dimension().0,
        ksk.output_key_lwe_dimension().0,
    );
    debug_assert!(lwe_list_out.ciphertext_modulus() == lwe_in.ciphertext_modulus());
    debug_assert!(lwe_in.ciphertext_modulus() == ksk.ciphertext_modulus());

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();
    let ciphertext_modulus = lwe_in.ciphertext_modulus();

    let align = CACHELINE_ALIGN;

    let (lwe_in_buffer_data, stack) = stack.collect_aligned(align, lwe_in.as_ref().iter().copied());
    let mut lwe_in_buffer =
        LweCiphertext::from_container(&mut *lwe_in_buffer_data, lwe_in.ciphertext_modulus());

    let (lwe_out_ks_buffer_data, stack) =
        stack.make_aligned_with(ksk.output_lwe_size().0, align, |_| u64::ZERO);
    let mut lwe_out_ks_buffer =
        LweCiphertext::from_container(lwe_out_ks_buffer_data.to_vec(), ksk.ciphertext_modulus());

    let (pbs_accumulator_data, stack) =
        stack.make_aligned_with(glwe_size.0 * polynomial_size.0, align, |_| u64::ZERO);
    let mut pbs_accumulator = GlweCiphertext::from_container(
        pbs_accumulator_data.to_vec(),
        polynomial_size,
        ciphertext_modulus,
    );

    let lwe_size = glwe_dimension
        .to_equivalent_lwe_dimension(polynomial_size)
        .to_lwe_size();
    let (lwe_out_pbs_buffer_data, stack) =
        stack.make_aligned_with(lwe_size.0, align, |_| u64::ZERO);
    let mut lwe_out_pbs_buffer = LweCiphertext::from_container(
        lwe_out_pbs_buffer_data.to_vec(),
        lwe_list_out.ciphertext_modulus(),
    );

    // We iterate on the list in reverse as we want to store the extracted MSB at index 0
    for (bit_idx, mut output_ct) in lwe_list_out.iter_mut().rev().enumerate() {
        // Block to keep the lwe_bit_left_shift_buffer_data alive only as long as needed
        {
            // Shift on padding bit
            let (lwe_bit_left_shift_buffer_data, _) = stack.collect_aligned(
                align,
                lwe_in_buffer
                    .as_ref()
                    .iter()
                    .map(|s| *s << (ciphertext_n_bits - delta_log.0 as u32 - bit_idx as u32 - 1)),
            );

            // Key switch to input PBS key
            keyswitch_lwe_ciphertext(
                &ksk,
                &LweCiphertext::from_container(
                    lwe_bit_left_shift_buffer_data,
                    lwe_in.ciphertext_modulus(),
                ),
                &mut lwe_out_ks_buffer,
            );
        }

        // Store the keyswitch output unmodified to the output list (as we need to to do other
        // computations on the output of the keyswitch)
        output_ct
            .as_mut()
            .copy_from_slice(lwe_out_ks_buffer.as_ref());

        // If this was the last extracted bit, break
        // we subtract 1 because if the number_of_bits_to_extract is 1 we want to stop right away
        if bit_idx == number_of_bits_to_extract - 1 {
            break;
        }

        // Add q/4 to center the error while computing a negacyclic LUT
        let out_ks_body = lwe_out_ks_buffer.get_mut_body().data;
        *out_ks_body = (*out_ks_body).wrapping_add(u64::ONE << (ciphertext_n_bits - 2));

        // Fill lut for the current bit (equivalent to trivial encryption as mask is 0s)
        // The LUT is filled with -alpha in each coefficient where alpha = delta*2^{bit_idx-1}
        for poly_coeff in &mut pbs_accumulator
            .as_mut_view()
            .get_mut_body()
            .as_mut_polynomial()
            .iter_mut()
        {
            *poly_coeff = u64::ZERO.wrapping_sub(u64::ONE << (delta_log.0 - 1 + bit_idx));
        }


        let vec_cts = vec![lwe_out_ks_buffer.clone()];
        let vec_luts = vec![pbs_accumulator.clone()];

        

        let out = gpu_pbs(streams, bsk, &vec_cts, &vec_luts);
        let mut out = out.into_lwe_ciphertext(&streams);

        // println!("Computing PBS...");
        // let start = std::time::Instant::now();
        // programmable_bootstrap_lwe_ciphertext(
        //     &lwe_out_ks_buffer,
        //     &mut lwe_out_pbs_buffer,
        //     &pbs_accumulator,
        //     &fourier_bsk,
        // );
        // println!("PBS took: {:?}", start.elapsed());

        // fourier_bsk.bootstrap(
        //     lwe_out_pbs_buffer.as_mut_view(),
        //     lwe_out_ks_buffer.as_view(),
        //     pbs_accumulator.as_view(),
        //     fft,
        //     stack,
        // );

        // Add alpha where alpha = delta*2^{bit_idx-1} to end up with an encryption of 0 if the
        // extracted bit was 0 and 1 in the other case
        let out_pbs_body = out.get_mut_body().data;

        *out_pbs_body = (*out_pbs_body).wrapping_add(u64::ONE << (delta_log.0 + bit_idx - 1));

        // Remove the extracted bit from the initial LWE to get a 0 at the extracted bit location.
        izip!(lwe_in_buffer.as_mut(), out.as_ref())
            .for_each(|(out, inp)| *out = (*out).wrapping_sub(*inp));
    }
}



macro_rules! izip {
    (@ __closure @ ($a:expr)) => { |a| (a,) };
    (@ __closure @ ($a:expr, $b:expr)) => { |(a, b)| (a, b) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr)) => { |((a, b), c)| (a, b, c) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr)) => { |(((a, b), c), d)| (a, b, c, d) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr)) => { |((((a, b), c), d), e)| (a, b, c, d, e) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr)) => { |(((((a, b), c), d), e), f)| (a, b, c, d, e, f) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr)) => { |((((((a, b), c), d), e), f), g)| (a, b, c, d, e, f, e) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr)) => { |(((((((a, b), c), d), e), f), g), h)| (a, b, c, d, e, f, g, h) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr)) => { |((((((((a, b), c), d), e), f), g), h), i)| (a, b, c, d, e, f, g, h, i) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr)) => { |(((((((((a, b), c), d), e), f), g), h), i), j)| (a, b, c, d, e, f, g, h, i, j) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr)) => { |((((((((((a, b), c), d), e), f), g), h), i), j), k)| (a, b, c, d, e, f, g, h, i, j, k) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr)) => { |(((((((((((a, b), c), d), e), f), g), h), i), j), k), l)| (a, b, c, d, e, f, g, h, i, j, k, l) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr)) => { |((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m)| (a, b, c, d, e, f, g, h, i, j, k, l, m) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr)) => { |(((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr, $o:expr)) => { |((((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n), o)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o) };

    ( $first:expr $(,)?) => {
        {
            #[allow(unused_imports)]
            use $tfhe::core_crypto::commons::utils::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
        }
    };
    ( $first:expr, $($rest:expr),+ $(,)?) => {
        {
            #[allow(unused_imports)]
            use tfhe::core_crypto::commons::utils::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
                $(.zip_checked($rest))*
                .map(izip!(@ __closure @ ($first, $($rest),*)))
        }
    };
}

pub(crate) use izip;

use crate::gpu::pbs::gpu_pbs;