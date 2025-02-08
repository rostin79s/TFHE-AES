use tfhe::integer::IntegerCiphertext;
use tfhe::integer::{
    ciphertext::BaseRadixCiphertext, 
    wopbs::WopbsKey,
};

use tfhe::shortint::Ciphertext;

use crate::tables::table::{SBOX, INV_SBOX};
use super::gen_lut::gen_lut;


use tfhe::core_crypto::prelude::*;


pub fn sbox(wopbs_key: &WopbsKey, ct_in: &mut BaseRadixCiphertext<Ciphertext>, inv: bool) {
    let message_mod = 2;
    let carry_mod = 1;

    let poly_size = 512;

    let f   : fn(u64) -> u64; 

    if inv {
        f = |x| INV_SBOX[x as usize] as u64;
    }
    else {
        f = |x| SBOX[x as usize] as u64;
    }

    // let start = std::time::Instant::now();
    
    let lut = gen_lut(message_mod, carry_mod, poly_size, ct_in, f);

    // let ct_res = wopbs_key.wopbs_without_padding(x, &lut);

    let total_bits_extracted = ct_in.blocks_mut().iter().fold(0usize, |acc, block| {
        acc + f64::log2((block.message_modulus.0 * block.carry_modulus.0) as f64) as usize
    });

    let wopbs_key_short = wopbs_key.clone().into_raw_parts();

    let extract_bits_output_lwe_size = 
        wopbs_key_short.pbs_server_key.key_switching_key.output_key_lwe_dimension().to_lwe_size();

    let mut extracted_bits_blocks = LweCiphertextList::new(
        0u64,
        extract_bits_output_lwe_size,
        LweCiphertextCount(total_bits_extracted),
        wopbs_key_short.param.ciphertext_modulus,
    );

    let mut bits_extracted_so_far = 0;
    // Extraction of each bit for each block

    let start = std::time::Instant::now();

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

    println!("Extracting bits: {:?}", start.elapsed());

    let start2 = std::time::Instant::now();

    // let vec_ct_out = wopbs_key_short.circuit_bootstrapping_vertical_packing(lut.as_ref(), &extracted_bits_blocks);


    // let output_list = wopbs_key_short.circuit_bootstrap_with_bits(
    //     extracted_bits_blocks,
    //     &lut.lut(),
    //     LweCiphertextCount(vec_lut.output_ciphertext_count().0),
    // );

    let lut2 = lut.as_ref().lut();
    let extracted_bits = &extracted_bits_blocks;
    let lut_size = lut.as_ref().output_ciphertext_count().0;
    let count = LweCiphertextCount(lut_size);

    let sks = &wopbs_key_short.wopbs_server_key;
    let fourier_bsk = &sks.bootstrapping_key;

    let output_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

    let mut output_cbs_vp_ct = LweCiphertextListOwned::new(
        0u64,
        output_lwe_size,
        count,
        wopbs_key_short.param.ciphertext_modulus,
    );
    let lut =
        PolynomialListView::from_container(lut2.as_ref(), fourier_bsk.polynomial_size());

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();

    // pub fn circuit_bootstrap_boolean_vertical_packing_scratch<Scalar>(
    //     lwe_list_in_count: LweCiphertextCount,
    //     lwe_list_out_count: LweCiphertextCount,
    //     lwe_in_size: LweSize,
    //     big_lut_polynomial_count: PolynomialCount,
    //     bsk_output_lwe_size: LweSize,
    //     glwe_size: GlweSize,
    //     fpksk_output_polynomial_size: PolynomialSize,
    //     level_cbs: DecompositionLevelCount,
    //     fft: FftView<'_>,
    // ) -> Result<StackReq, SizeOverflow>

    let mut buffers = ComputationBuffers::new();

    let buffer_size_req =
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required();

    let stack = tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
        extracted_bits.lwe_ciphertext_count(),
        output_cbs_vp_ct.lwe_ciphertext_count(),
        extracted_bits.lwe_size(),
        lut.polynomial_count(),
        fourier_bsk.output_lwe_dimension().to_lwe_size(),
        fourier_bsk.glwe_size(),
        wopbs_key_short.cbs_pfpksk.output_polynomial_size(),
        wopbs_key_short.param.cbs_level,
        fft,
    );

    let buffer_size_req = buffer_size_req.max(stack.unwrap().unaligned_bytes_required());
    buffers.resize(buffer_size_req);
    
//     circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
//         extracted_bits,
//         &mut output_cbs_vp_ct,
//         &lut,
//         bsk,
//         &self.cbs_pfpksk,
//         self.param.cbs_base_log,
//         self.param.cbs_level,
//         fft,
//         stack,
//     );
// }

    use tfhe::shortint::server_key::ShortintBootstrappingKey;
    match &sks.bootstrapping_key {
        ShortintBootstrappingKey::Classic(bsk) => {
            circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
                extracted_bits,
                &mut output_cbs_vp_ct,
                &lut,
                bsk,
                &wopbs_key_short.cbs_pfpksk,
                wopbs_key_short.param.cbs_base_log,
                wopbs_key_short.param.cbs_level,
                fft,
                buffers.stack(),
            );
        }
        ShortintBootstrappingKey::MultiBit { .. } => {
            // return Err(WopbsKeyCreationError::UnsupportedMultiBit);
        }
    };
    // circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
    //     &extracted_bits,
    //     &mut output_cbs_vp_ct,
    //     &lut.as_view(),
    //     &fourier_bsk,
    //     &cbs_pfpksk,
    //     cbs_base_log,
    //     cbs_level_count,
    //     fft,
    //     buffers.stack(),
    // );

   

    let output_list = output_cbs_vp_ct;


    assert_eq!(
        output_list.lwe_ciphertext_count().0,
        lut_size
    );

    let output_container = output_list.into_container();
    let ciphertext_modulus = wopbs_key_short.param.ciphertext_modulus;
    let lwes: Vec<_> = output_container
        .chunks_exact(output_container.len() / lut_size)
        .map(|s| LweCiphertextOwned::from_container(s.to_vec(), ciphertext_modulus))
        .collect();

    assert_eq!(lwes.len(), lut_size);
    let vec_ct_out = lwes;

    println!("Circuit Bootstrapping: {:?}", start2.elapsed());

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

    
    *ct_in = out;

    // println!("Sbox: {:?}", start.elapsed());
}

