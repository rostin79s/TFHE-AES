use std::u8;

use tfhe::integer::wopbs::IntegerWopbsLUT;
use tfhe::integer::IntegerCiphertext;
use tfhe::integer::{
    ciphertext::BaseRadixCiphertext, 
};
use tfhe::shortint::wopbs::WopbsKey;

use tfhe::shortint::Ciphertext;

use crate::tables::table::{SBOX, INV_SBOX};
use super::gen_lut::gen_lut;


use tfhe::core_crypto::prelude::*;

// use dyn_stack::PodStack;

pub fn mul2(x: u8) -> u8 {
    let mut y = x << 1;
    if (x & 0x80) != 0 { // Check if the highest bit (b7) is set
        y ^= 0x1B;       // XOR with the reduction polynomial
    }
    y & 0xFF // Ensure the result is still within 8 bits
}
pub fn mul3(x: u8) -> u8 {
    mul2(x) ^ x
}
pub fn mul9(x: u8) -> u8 {
    mul2(mul2(mul2(x))) ^ x
}
pub fn mul11(x: u8) -> u8 {
    mul2(mul2(mul2(x)) ^ x) ^ x
}
pub fn mul13(x: u8) -> u8 {
    mul2(mul2(mul2(x) ^ x)) ^ x
}
pub fn mul14(x: u8) -> u8 {
    mul2(mul2(mul2(x) ^ x) ^ x)
}

pub fn key_sbox(wopbs_key: &tfhe::integer::wopbs::WopbsKey, wopbs_key_short: &tfhe::shortint::wopbs::WopbsKey, ct_in: &mut BaseRadixCiphertext<Ciphertext>){
    let f = |x| SBOX[x as usize] as u64;
    let lut = gen_lut(
        wopbs_key_short.param.message_modulus.0 as usize,
        wopbs_key_short.param.carry_modulus.0 as usize,
        wopbs_key_short.param.polynomial_size.0,
        ct_in,
        f,
    );
    let ct_res = wopbs_key.wopbs_without_padding(ct_in, &lut);
    *ct_in = ct_res;
}

pub fn sbox(wopbs_key_short: &WopbsKey, ct_in: &mut BaseRadixCiphertext<Ciphertext>, inv: bool) -> Vec<BaseRadixCiphertext<Ciphertext>> {

    let mut functions: Vec<fn(u64) -> u64> = vec![];
    let mut luts: Vec<IntegerWopbsLUT> = vec![];

    if inv {
        functions.push(|x| mul9(INV_SBOX[x as usize] as u8) as u64);
        functions.push(|x| mul11(INV_SBOX[x as usize] as u8) as u64);
        functions.push(|x| mul13(INV_SBOX[x as usize] as u8) as u64);
        functions.push(|x| mul14(INV_SBOX[x as usize] as u8) as u64);
    } else {
        functions.push(|x| SBOX[x as usize] as u64);
        // functions.push(|x| SBOX[x as usize] as u8 as u64);
        // functions.push(|x| SBOX[x as usize] as u8 as u64);
    }


    for f in functions.iter() {
        let lut = gen_lut(
            wopbs_key_short.param.message_modulus.0 as usize,
            wopbs_key_short.param.carry_modulus.0 as usize,
            wopbs_key_short.param.polynomial_size.0,
            ct_in,
            *f,
        );
        luts.push(lut);
    }



    let extracted_bits = custom_extract_bits(ct_in, wopbs_key_short);

    let sks = &wopbs_key_short.wopbs_server_key;
    let fourier_bsk = &sks.bootstrapping_key;

    
    let mut vec_poly_lut: Vec<PolynomialList<&[u64]>> = Vec::new();
    let mut vec_output_cbs_vp_ct: Vec<LweCiphertextList<Vec<u64>>> = Vec::new();
    let mut acc_luts: Vec<PlaintextList<&[u64]>> = Vec::new();
    for i in 0..luts.len() {
        acc_luts.push(luts[i].as_ref().lut());
    }
    for i in 0..luts.len() {
        // let extracted_bits = &extracted_bits_blocks;
        let lut_size = luts[i].as_ref().output_ciphertext_count().0;
        let count = LweCiphertextCount(lut_size);


        

        let output_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

        let output_cbs_vp_ct = LweCiphertextListOwned::new(
            0u64,
            output_lwe_size,
            count,
            wopbs_key_short.param.ciphertext_modulus,
        );
        vec_output_cbs_vp_ct.push(output_cbs_vp_ct);


        let poly_lut =
            PolynomialListView::from_container(acc_luts[i].as_ref(), fourier_bsk.polynomial_size());
            
        vec_poly_lut.push(poly_lut);
    }

    

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();




    let mut buffers = ComputationBuffers::new();

    custom_set_buffers(&mut buffers, &fourier_bsk, &wopbs_key_short, &vec_poly_lut, &extracted_bits, &vec_output_cbs_vp_ct, &fft);
    

  


    use tfhe::shortint::server_key::ShortintBootstrappingKey;
    match &sks.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => {
            circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
                &extracted_bits,
                &mut vec_output_cbs_vp_ct[0],
                &vec_poly_lut[0],
                bsk,
                &wopbs_key_short.cbs_pfpksk,
                wopbs_key_short.param.cbs_base_log,
                wopbs_key_short.param.cbs_level,
                fft,
                buffers.stack(),
            );
            // many_circuit_bootstrap_boolean_vertical_packing(
            //     vec_poly_lut,
            //     bsk.as_view(),
            //     vec_output_cbs_vp_ct.iter_mut().map(|x| x.as_mut_view()).collect(),
            //     extracted_bits.as_view(),
            //     wopbs_key_short.cbs_pfpksk.as_view(),
            //     wopbs_key_short.param.cbs_level,
            //     wopbs_key_short.param.cbs_base_log,
            //     fft,
            //     buffers.stack(),
            // );
        }
        ShortintBootstrappingKey::MultiBit { .. } => {
            // return Err(WopbsKeyCreationError::UnsupportedMultiBit);
        }
    };
   

    let mut out_list: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();
    for (i,output_list) in vec_output_cbs_vp_ct.iter().enumerate() {
        let output_container = output_list.as_ref();
        let ciphertext_modulus = wopbs_key_short.param.ciphertext_modulus;
        let lwes: Vec<_> = output_container
            .chunks_exact(output_container.len() / luts[i].as_ref().output_ciphertext_count().0)
            .map(|s| LweCiphertextOwned::from_container(s.to_vec(), ciphertext_modulus))
            .collect();

        let vec_ct_out = lwes;


        let mut ct_vec_out = vec![];
        for (block, block_out) in ct_in.blocks().iter().zip(vec_ct_out) {
            ct_vec_out.push(tfhe::shortint::Ciphertext::new(
                block_out,
                tfhe::shortint::parameters::Degree::new(block.message_modulus.0 - 1),
                tfhe::shortint::parameters::NoiseLevel::NOMINAL,
                block.message_modulus,
                block.carry_modulus,
                block.pbs_order,
            ));
        }

        let out = BaseRadixCiphertext::from_blocks(ct_vec_out);
        out_list.push(out);

    }


    
    
    return out_list;

    // println!("Sbox: {:?}", start.elapsed());
}

use tfhe::shortint::server_key::ShortintBootstrappingKey;

// &mut buffers, &fourier_bsk, &wopbs_key_short, &lut, &extracted_bits, &output_cbs_vp_ct, &fft
pub fn custom_set_buffers(buffers: &mut ComputationBuffers, fourier_bsk: &ShortintBootstrappingKey, wopbs_key_short: &WopbsKey, vec_poly_lut: &Vec<PolynomialList<&[u64]>>, extracted_bits: &LweCiphertextList<Vec<u64>>, vec_output_cbs_vp_ct: &Vec<LweCiphertextList<Vec<u64>>>, fft: &FftView){

    let buffer_size_req =
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(*fft)
            .unwrap()
            .unaligned_bytes_required();

    

    // this is only for one vertical packing. We need to do this for all vertical packings
    let stack = tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
        extracted_bits.lwe_ciphertext_count(),
        vec_output_cbs_vp_ct[0].lwe_ciphertext_count(),
        extracted_bits.lwe_size(),
        vec_poly_lut[0].polynomial_count(),
        fourier_bsk.output_lwe_dimension().to_lwe_size(),
        fourier_bsk.glwe_size(),
        wopbs_key_short.cbs_pfpksk.output_polynomial_size(),
        wopbs_key_short.param.cbs_level,
        *fft,
    );

    let buffer_size_req = buffer_size_req.max(stack.unwrap().unaligned_bytes_required());
    buffers.resize(buffer_size_req);


    // // now we resize for the rest of the vertical packings.
    // for i in 1..vec_poly_lut.len() {
    //     let stack = tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::vertical_packing_scratch::<u64>(
    //         fourier_bsk.glwe_size(), wopbs_key_short.cbs_pfpksk.output_polynomial_size(), vec_poly_lut[i].polynomial_count(), extracted_bits.lwe_ciphertext_count().0, *fft
    //     );

    //     let buffer_size_req = buffer_size_req.max(stack.unwrap().unaligned_bytes_required());
    //     buffers.resize(buffer_size_req);
    // }

}



pub fn custom_extract_bits(ct_in: &mut BaseRadixCiphertext<Ciphertext>, wopbs_key_short: &WopbsKey) -> LweCiphertextList<Vec<u64>> {
    let total_bits_extracted = ct_in.blocks_mut().iter().fold(0usize, |acc, block| {
        acc + f64::log2((block.message_modulus.0 * block.carry_modulus.0) as f64) as usize
    });


    let extract_bits_output_lwe_size = 
        wopbs_key_short.pbs_server_key.key_switching_key.output_key_lwe_dimension().to_lwe_size();

    let mut extracted_bits_blocks = LweCiphertextList::new(
        0u64,
        extract_bits_output_lwe_size,
        LweCiphertextCount(total_bits_extracted),
        wopbs_key_short.param.ciphertext_modulus,
    );

    let mut bits_extracted_so_far = 0;

    for block in ct_in.blocks().iter().rev() {
        let block_modulus = block.message_modulus.0 * block.carry_modulus.0;
        let delta = (1_u64 << 63) / (block_modulus / 2);
        // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
        let delta_log = DeltaLog(delta.ilog2() as usize);
        let nb_bit_to_extract =
            f64::log2((block.message_modulus.0 * block.carry_modulus.0) as f64) as usize;

        let extract_from_bit = bits_extracted_so_far;
        let extract_to_bit = extract_from_bit + nb_bit_to_extract;
        bits_extracted_so_far += nb_bit_to_extract;

        let mut lwe_sub_list =
            extracted_bits_blocks.get_sub_mut(extract_from_bit..extract_to_bit);

        wopbs_key_short.extract_bits_assign(
            delta_log,
            block,
            ExtractedBitsCount(nb_bit_to_extract),
            &mut lwe_sub_list,
        );
    }
    return extracted_bits_blocks;
}

use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListMutView;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::circuit_bootstrap_boolean;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::vertical_packing;


use aligned_vec::CACHELINE_ALIGN;
use tfhe_fft::c64;

use dyn_stack::PodStack;

pub fn many_circuit_bootstrap_boolean_vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
    big_lut_as_polynomial_list: Vec<PolynomialList<&[Scalar]>>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    mut lwe_list_out: Vec<LweCiphertextList<&mut [Scalar]>>,
    lwe_list_in: LweCiphertextList<&[Scalar]>,
    pfpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[Scalar]>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: &mut PodStack,
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
        |_| Scalar::ZERO,
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

    for (lwe_in, ggsw) in izip!(lwe_list_in.iter(), ggsw_list.as_mut_view().into_ggsw_iter()) {
        circuit_bootstrap_boolean(
            fourier_bsk,
            lwe_in,
            ggsw_res.as_mut_view(),
            DeltaLog(Scalar::BITS - 1),
            pfpksk_list.as_view(),
            fft,
            stack,
        );

        ggsw.fill_with_forward_fourier(ggsw_res.as_view(), fft, stack);
    }

    // We do vertical packing for each LUT and store the result in lwe_list_out.
    for i in 0..lwe_list_out.len() {
        let number_of_luts = lwe_list_out[i].lwe_ciphertext_count().0;

        let small_lut_size = big_lut_as_polynomial_list[i].polynomial_count().0 / number_of_luts;


        for (lut, lwe_out) in izip!(
            big_lut_as_polynomial_list[i].chunks_exact(small_lut_size),
            lwe_list_out[i].iter_mut(),
        ) {
            vertical_packing(lut, lwe_out, ggsw_list.as_view(), fft, stack);
        }
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