use super::*;

fn round_div(numerator: u128, denominator: u128) -> u128 {
    // Compute the quotient and remainder for rounding
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    // Multiply remainder by 2 (safe because denominator is small in our use case)
    let double_remainder = remainder * 2;
    if double_remainder < denominator {
        quotient
    } else if double_remainder > denominator {
        quotient + 1
    } else {
        // Tie: round to even (i.e. if quotient is even, keep it; if odd, round up)
        if quotient % 2 == 0 {
            quotient
        } else {
            quotient + 1
        }
    }
}

pub fn cpu_pbs_modulus_switch<Scalar: UnsignedInteger + CastInto<usize>>(
    input: u64,
    polynomial_size: PolynomialSize,
    v: usize,
    x: i32
) -> usize {
    cpu_modulus_switch::<u64>(input, polynomial_size.to_blind_rotation_input_modulus_log(), v as i32, x).cast_into()
}

pub fn cpu_modulus_switch<Scalar: UnsignedInteger + CastFrom<u64>>(
    input: u64,
    log_modulus: CiphertextModulusLog,
    v: i32,
    x: i32
) -> Scalar {
    // let input2: Scalar = Scalar::cast_from(input);
    // let temp2 = input2.wrapping_add(Scalar::ONE << (Scalar::BITS - log_modulus.0 - 1));
    // let temp2 = temp2 >> (Scalar::BITS - log_modulus.0);
    
    // let mask = !((Scalar::ONE << v) - Scalar::ONE);
    // let temp2 = temp2 & mask;

    let two_n = 1 << log_modulus.0;
    
    // scale = twoN * (2^(k - v))
    // Here k-v might be negative so we do the proper branch
    // let scale = two_n;
    let scale: u128 = if x >= v {
        two_n * (1u128 << (x - v) as u32)
    } else {
        // When x-v is negative, use division.
        two_n / (1u128 << ((v - x) as u32))
    };

    // First rounding: compute round((ai * scale) / q)
    let ai = input as u128;
    let prod = ai * scale;
    let exponent = 64 ;
    // println!("exponent: {}", exponent);
    let q = 1u128 << exponent;
    let temp_rounded = round_div(prod, q);

    // Multiply by 2^v and round again.
    // Note: Because temp_rounded is an integer and 2^v is an integer,
    // the multiplication is exact and no additional rounding is needed.
    let second_result = temp_rounded * (1u128 << (v as u32));

    // Final result is modulo 2N
    let result = second_result % two_n;
    let result = result as u64;

    return Scalar::cast_from(result);
    
}

fn cpu_genpbs_blind_rotate_assign(
    input: &LweCiphertext<Vec<u64>>,
    lut: &mut GlweCiphertext<Vec<u64>>,
    fourier_bsk: &FourierLweBootstrapKeyView<'_>,
    v: usize,
    x: i32
) {
    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        blind_rotate_assign_mem_optimized_requirement::<u64>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();
    let mut lut = lut.as_mut_view();


    
    let (lwe_mask, lwe_body) = input.get_mask_and_body();

    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());
    let monomial_degree = MonomialDegree(cpu_pbs_modulus_switch::<u64>(*lwe_body.data, lut_poly_size, v, x));

    lut.as_mut_polynomial_list()
    .iter_mut()
    .for_each(|mut poly| {
        let (tmp_poly, _) = stack.make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

        let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
        tmp_poly.as_mut().copy_from_slice(poly.as_ref());
        polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
    });

    // We initialize the ct_0 used for the successive cmuxes
    let mut ct0 = lut;
    let (ct1, stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
    let mut ct1 =
        GlweCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

    for (lwe_mask_element, bootstrap_key_ggsw) in
        izip!(lwe_mask.as_ref().iter(), fourier_bsk.into_ggsw_iter())
    {
        if *lwe_mask_element != u64::ZERO {
            let monomial_degree =
                MonomialDegree(cpu_pbs_modulus_switch::<u64>(*lwe_mask_element, lut_poly_size, v, x));

            // we effectively inline the body of cmux here, merging the initial subtraction
            // operation with the monic polynomial multiplication, then performing the external
            // product manually

            // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
            // ct_1 <- (ct_0 * X^{a_hat}) - ct_0
            for (mut ct1_poly, ct0_poly) in izip!(
                ct1.as_mut_polynomial_list().iter_mut(),
                ct0.as_polynomial_list().iter(),
            ) {
                polynomial_wrapping_monic_monomial_mul_and_subtract(
                    &mut ct1_poly,
                    &ct0_poly,
                    monomial_degree,
                );
            }

            // as_mut_view is required to keep borrow rules consistent
            // second step of cmux
            tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign(
                ct0.as_mut_view(),
                bootstrap_key_ggsw,
                ct1.as_view(),
                fft,
                stack,
            );
        }
    }

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}


pub fn cpu_pbsmany
(
    fourier_bsk: &FourierLweBootstrapKeyView<'_>,
    ct: &LweCiphertext<Vec<u64>>,
    lut: &mut GlweCiphertext<Vec<u64>>,
    v: usize,
    x: i32
) -> Vec<LweCiphertext<Vec<u64>>>
{
    println!("v: {} ", v);
    cpu_genpbs_blind_rotate_assign(&ct, lut, &fourier_bsk, v, x);

    let function_count = 2_i32.pow(v as u32) as usize;
    let mut outputs = Vec::with_capacity(function_count);
    let ciphertext_modulus = ct.ciphertext_modulus();
    let lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

    for fn_idx in 0..function_count {
        let monomial_degree = MonomialDegree(fn_idx);
        // println!("monomial degree: {:?}", monomial_degree.0);
        let mut output_shortint_ct = LweCiphertext::new(0, lwe_size, ciphertext_modulus);

        extract_lwe_sample_from_glwe_ciphertext(
            &lut,
            &mut output_shortint_ct,
            monomial_degree,
        );
        outputs.push(output_shortint_ct);
    }

    outputs
}

pub fn cpu_gen_pbsmany_lut
(
    pbs_params: &FHEParameters,
    vec_functions:  Vec<impl Fn(u64) -> u64>,
    x: i32
) -> (GlweCiphertext<Vec<u64>> , usize)
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
            params.message_modulus.0 * params.carry_modulus.0,
            params.polynomial_size,
            params.glwe_dimension.to_glwe_size(),
            params.ciphertext_modulus,
        ),
    };

    let mut acc = GlweCiphertext::new(
        0,
        glwe_size,
        polynomial_size,
        ciphertext_modulus,
    );

    let mut accumulator_view = acc.as_mut_view();
    let mut body = accumulator_view.get_mut_body();
    let p = plaintext_modulus.ilog2() as i32 - x;
    println!("p: {}", p);
    let delta = 1 << (64 - p);
    let function_count = vec_functions.len();
    let box_size = polynomial_size.0 >> p;
    // println!("box_size: {}", box_size);
    {
        let accumulator_u64 = body.as_mut();
        // Clear in case we don't fill the full accumulator so that the remainder part is 0
        accumulator_u64.as_mut().fill(0u64);
        for (msg_value, acc_box) in accumulator_u64.chunks_exact_mut(box_size).enumerate(){
            // println!("msg_value: {}", msg_value);
            for (index, value) in acc_box.iter_mut().enumerate(){
                let function_eval = vec_functions[index%function_count](msg_value as u64);
                // *value = (function_eval % plaintext_modulus as u64) * delta;
                *value = (function_eval as u64) * delta;
            }
        }
    }

    let mut lut = vec![0u64; 2048]; // Initialize polynomial
    for j in 0..16 {
        for k in 0..32 {
            for i in 0..4 {
                let index = j*128 + k*4 + i;
                let eval = vec_functions[i](j as u64);
                lut[index] = (eval  as u64) * delta;
            }
        }
    }
    // lut.rotate_right(64);
    // println!("lut: {:?}", lut);
    
    let half_box_size = box_size / 2;

    // let mut poly_body = body.as_mut_polynomial();
    // polynomial_wrapping_monic_monomial_mul_assign(&mut poly_body, MonomialDegree(half_box_size));

    // assert_eq!(lut, body.as_ref().to_vec());
    let accumulator_u64 = body.as_mut();
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }
    accumulator_u64.rotate_left(half_box_size);
    

    // println!("accumulator: {:?}", poly_body);
    let v = vec_functions.len().ilog2() as usize;
    return (acc, v);
}