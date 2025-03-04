pub mod key_switch;
pub mod pbs;
pub mod extract_bits;
pub mod cbs_vp;


use aligned_vec::{ABox, ConstAlign};
use tfhe::{
    core_crypto::{
        backward_compatibility::commons::ciphertext_modulus, gpu::{
            convert_lwe_keyswitch_key_async, cuda_keyswitch_lwe_ciphertext, lwe_ciphertext_list::CudaLweCiphertextList, lwe_keyswitch_key::CudaLweKeyswitchKey, vec::{
                CudaVec,
                GpuIndex
            }, CudaStreams

        }, prelude::{
            keyswitch_lwe_ciphertext, LweCiphertext, LweCiphertextCount, LweCiphertextList, LweKeyswitchKey, LweSize
        }
    }, integer::wopbs, shortint::{
        prelude::LweDimension, MultiBitPBSParameters, WopbsParameters
    }
};


use tfhe::integer::gpu::CudaServerKey;
use tfhe::integer::ClientKey;


use tfhe::shortint::gen_keys;
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::wopbs::*;
use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::core_crypto::algorithms::lwe_keyswitch;
use tfhe::core_crypto::prelude::*;

use tfhe::core_crypto::gpu::algorithms::cuda_programmable_bootstrap_lwe_ciphertext;
use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use tfhe::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use tfhe::core_crypto::gpu::cuda_multi_bit_programmable_bootstrap_lwe_ciphertext;



use tfhe::core_crypto::commons::math::random::BoundedDistribution;
use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use tfhe::integer::backward_compatibility::ciphertext;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::parameters::{LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_3_KS_PBS, LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS, LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS, PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64, V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64};
use tfhe::shortint::Ciphertext;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListMutView;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::circuit_bootstrap_boolean;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::vertical_packing;
use dyn_stack::PodStack;
use tfhe_fft::c64;

use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use aligned_vec::CACHELINE_ALIGN;

pub enum FHEParameters{
    MultiBit(MultiBitPBSParameters),
    Wopbs(WopbsParameters),
}

pub fn cpu_seed(
    pbs_params: &FHEParameters
) -> (Box<dyn Seeder>, EncryptionRandomGenerator<DefaultRandomGenerator>, LweSecretKey<Vec<u64>>, GlweSecretKey<Vec<u64>>, LweSecretKey<Vec<u64>>)
{
    let (small_lwe_dimension, glwe_dimension, polynomial_size) = match pbs_params {
        FHEParameters::MultiBit(params) => (
            params.lwe_dimension,
            params.glwe_dimension,
            params.polynomial_size,
        ),
        FHEParameters::Wopbs(params) => (
            params.lwe_dimension,
            params.glwe_dimension,
            params.polynomial_size,
        ),
    };

    let mut boxed_seeder = new_seeder();
    let seeder: &mut dyn Seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let encryption_generator =
    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    println!("Generating keys right now...");

    let small_lwe_sk: LweSecretKey<Vec<u64>> =
    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
    let glwe_sk: GlweSecretKey<Vec<u64>> =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let big_lwe_sk: LweSecretKey<Vec<u64>> = glwe_sk.clone().into_lwe_secret_key();

    return (boxed_seeder, encryption_generator, small_lwe_sk, glwe_sk, big_lwe_sk);
}

pub fn cpu_gen_ksk(
    pbs_params: &MultiBitPBSParameters,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>,
    big_lwe_sk: &LweSecretKey<Vec<u64>>
) -> LweKeyswitchKey<Vec<u64>>
{
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        pbs_params.ks_base_log,
        pbs_params.ks_level,
        pbs_params.lwe_noise_distribution,
        pbs_params.ciphertext_modulus,
        encryption_generator,
    );
    return ksk;
}

pub fn cpu_gen_bsk
(
    pbs_params: &FHEParameters, 
    boxed_seeder: &mut Box<dyn Seeder>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>, 
    glwe_sk: &GlweSecretKey<Vec<u64>>
) -> (LweBootstrapKey<Vec<u64>>, FourierLweBootstrapKey<ABox<[c64], ConstAlign<128>>>)
{
    let (pbs_base_log, pbs_level, glwe_noise_distribution, ciphertext_modulus) = match pbs_params {
        FHEParameters::MultiBit(params) => (
            params.pbs_base_log,
            params.pbs_level,
            params.glwe_noise_distribution,
            params.ciphertext_modulus,
        ),
        FHEParameters::Wopbs(params) => (
            params.pbs_base_log,
            params.pbs_level,
            params.glwe_noise_distribution,
            params.ciphertext_modulus,
        ),
    };

    let bsk = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_noise_distribution,
        ciphertext_modulus,
        boxed_seeder.as_mut(),
    );

    let bsk: LweBootstrapKeyOwned<u64> = bsk.decompress_into_lwe_bootstrap_key();
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
    return (bsk, fourier_bsk);
}

pub fn cpu_gen_multibsk
(
    pbs_params: &MultiBitPBSParameters, 
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>, 
    glwe_sk: &GlweSecretKey<Vec<u64>>
) -> (LweMultiBitBootstrapKey<Vec<u64>>, FourierLweMultiBitBootstrapKey<ABox<[c64], ConstAlign<128>>>)
{
    let glwe_dimension = pbs_params.glwe_dimension;
    let polynomial_size = pbs_params.polynomial_size;
    let pbs_base_log = pbs_params.pbs_base_log;
    let pbs_level = pbs_params.pbs_level;
    let small_lwe_dimension = pbs_params.lwe_dimension;
    let glwe_noise_distribution = pbs_params.glwe_noise_distribution;
    let ciphertext_modulus = pbs_params.ciphertext_modulus;


    let grouping_factor = pbs_params.grouping_factor;
    let mut bsk = LweMultiBitBootstrapKey::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
        small_lwe_dimension,
        grouping_factor,
        ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        &mut bsk,
        glwe_noise_distribution,
        encryption_generator,
    );

    let mut multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.grouping_factor(),
    );

    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut multi_bit_bsk);
    return (bsk, multi_bit_bsk);
}

pub fn cpu_gen_wopbs_keys
(
    pbs_params: &MultiBitPBSParameters,
    small_lwe_sk: &LweSecretKey<Vec<u64>>,
    big_lwe_sk: &LweSecretKey<Vec<u64>>,
    wopbs_parameters: &WopbsParameters,
    wopbs_encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    wopbs_small_lwe_secret_key: &LweSecretKey<Vec<u64>>,
    wopbs_big_lwe_secret_key: &LweSecretKey<Vec<u64>>,
    wopbs_glwe_secret_key: &GlweSecretKey<Vec<u64>>,
) -> (LweKeyswitchKey<Vec<u64>>, LweKeyswitchKey<Vec<u64>>, LweKeyswitchKey<Vec<u64>>, LwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>)
{
    //KSK encryption_key -> small WoPBS key (used in the 1st KS in the extract bit)
    let ksk_wopbs_large_to_wopbs_small = allocate_and_generate_new_lwe_keyswitch_key(
        &wopbs_big_lwe_secret_key,
        &wopbs_small_lwe_secret_key,
        wopbs_parameters.ks_base_log,
        wopbs_parameters.ks_level,
        wopbs_parameters.lwe_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        wopbs_encryption_generator,
    );



    // KSK to convert from input ciphertext key to the wopbs input one
    let ksk_pbs_large_to_wopbs_large = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &wopbs_big_lwe_secret_key,
        pbs_params.ks_base_log,
        pbs_params.ks_level,
        wopbs_parameters.lwe_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        wopbs_encryption_generator,
    );

    // KSK large_wopbs_key -> small PBS key (used after the WoPBS computation to compute a
    // classical PBS. This allows compatibility between PBS and WoPBS
    let ksk_wopbs_large_to_pbs_small = allocate_and_generate_new_lwe_keyswitch_key(
        &wopbs_big_lwe_secret_key,
        &small_lwe_sk,
        pbs_params.ks_base_log,
        pbs_params.ks_level,
        pbs_params.lwe_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        wopbs_encryption_generator,
    );

    let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &wopbs_big_lwe_secret_key,
        &wopbs_glwe_secret_key,
        wopbs_parameters.pfks_base_log,
        wopbs_parameters.pfks_level,
        wopbs_parameters.pfks_noise_distribution,
        wopbs_parameters.ciphertext_modulus,
        wopbs_encryption_generator,
    );
    return (ksk_wopbs_large_to_wopbs_small, ksk_pbs_large_to_wopbs_large, ksk_wopbs_large_to_pbs_small, cbs_pfpksk);
}

pub fn cpu_encrypt
(
    pbs_params: &MultiBitPBSParameters,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>,
    clear: u64,
) -> LweCiphertext<Vec<u64>>
{
    let plaintext_modulus = pbs_params.message_modulus.0 * pbs_params.carry_modulus.0;
    let delta = (1_u64 << 63) / plaintext_modulus;
    let lwe_noise_distribution = pbs_params.lwe_noise_distribution;
    let ciphertext_modulus = pbs_params.ciphertext_modulus;

    let plaintext1 = Plaintext(clear * delta);
    let ct: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext1,
        lwe_noise_distribution,
        ciphertext_modulus,
        encryption_generator,
    );
    return ct;
}

pub fn cpu_decrypt
(
    pbs_params: &FHEParameters,
    big_lwe_sk: &LweSecretKey<Vec<u64>>,
    ct: &LweCiphertext<Vec<u64>>,
) -> u64
{
    let plaintext_modulus = match pbs_params {
        FHEParameters::MultiBit(params) => params.message_modulus.0 * params.carry_modulus.0,
        FHEParameters::Wopbs(params) => params.message_modulus.0 * params.carry_modulus.0,
    };

    let delta = (1_u64 << 63) / plaintext_modulus;
    let dec: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, &ct);
    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog((plaintext_modulus.ilog2() + 1) as usize), DecompositionLevelCount(1));
    let dec: u64 = signed_decomposer.closest_representable(dec.0) / delta;

    return dec;
}

pub fn cpu_veclwe_to_lwelist(
    vec_lwe_in: &Vec<LweCiphertext<Vec<u64>>>,
) -> LweCiphertextList<Vec<u64>>
{
    let lwe_size = vec_lwe_in[0].lwe_size();
    let ciphertext_modulus = vec_lwe_in[0].ciphertext_modulus();

    let mut cts_container = Vec::new();
    for lwe_in in vec_lwe_in.iter(){
        cts_container.extend(lwe_in.clone().into_container());
    }

    let lwe_list_out = LweCiphertextList::from_container(cts_container, lwe_size, ciphertext_modulus);
    return lwe_list_out;
}
