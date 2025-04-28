pub mod key_switch;
pub mod pbs;
pub mod extract_bits;
pub mod cbs_vp;
pub mod pbsmany;




use aes::cipher::typenum::Pow;
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
        prelude::LweDimension, CarryModulus, ClassicPBSParameters, MaxNoiseLevel, MessageModulus, MultiBitPBSParameters, PBSParameters, WopbsParameters
    }
};


use tfhe::integer::gpu::CudaServerKey;
use tfhe::integer::ClientKey;


use tfhe::shortint::gen_keys;
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::wopbs::*;
use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::core_crypto::algorithms::lwe_keyswitch;
use tfhe::core_crypto::prelude::*;

use tfhe::core_crypto::gpu::algorithms::cuda_programmable_bootstrap_lwe_ciphertext;
use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use tfhe::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use tfhe::core_crypto::gpu::cuda_multi_bit_programmable_bootstrap_lwe_ciphertext;


use tfhe::core_crypto::commons::math::decomposition::*;
use tfhe::core_crypto::commons::math::random::BoundedDistribution;
use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use tfhe::integer::backward_compatibility::ciphertext;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::Ciphertext;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListMutView;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::circuit_bootstrap_boolean;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::vertical_packing;

use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use tfhe::shortint::ciphertext::MaxDegree;
use tfhe::shortint::parameters::Degree;
use tfhe::shortint::server_key::ManyLookupTableOwned;

use tfhe::core_crypto::prelude::GlweCiphertext;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::core_crypto::prelude::keyswitch_lwe_ciphertext_into_glwe_ciphertext;
use tfhe::core_crypto::prelude::ContiguousEntityContainerMut;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::core_crypto::prelude::MonomialDegree;
use tfhe::core_crypto::prelude::slice_algorithms::slice_wrapping_add_assign;
use tfhe::core_crypto::prelude::trivially_encrypt_lwe_ciphertext;
use tfhe::core_crypto::prelude::Plaintext;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_div_assign;

use tfhe::core_crypto::fft_impl::fft64::math::fft::{Fft, FourierPolynomialList};
use tfhe::conformance::ParameterSetConformant;
use tfhe::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
use tfhe::core_crypto::backward_compatibility::fft_impl::FourierLweBootstrapKeyVersions;
use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
use tfhe::core_crypto::commons::math::torus::UnsignedTorus;
use tfhe::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use tfhe::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize,
    PolynomialSize,
};
use tfhe::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, IntoContainerOwned, Split,
};
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::common::{pbs_modulus_switch, FourierBootstrapKey};
use tfhe::core_crypto::fft_impl::fft64::math::fft::par_convert_polynomials_list_to_fourier;
use tfhe::core_crypto::prelude::{CiphertextCount, CiphertextModulus, ContainerMut};

use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::*;
// use tfhe::core_crypto::commons::utils::izip;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign;

use aligned_vec::ABox;
use tfhe_fft::c64;
use aligned_vec::ConstAlign;
use dyn_stack::PodStack;
use aligned_vec::CACHELINE_ALIGN;


use tfhe::core_crypto::commons::utils::izip;


pub enum FHEParameters{
    MultiBit(MultiBitPBSParameters),
    Wopbs(WopbsParameters),
    PBS(ClassicPBSParameters),
}

// - 6 :   2, 10,  812,    1, 23,     3,  5,     77, 9.9e-14
pub const PBS_PARAMS_no_padding:
    ClassicPBSParameters =
    ClassicPBSParameters {
    lwe_dimension: LweDimension(748),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.3747142481837397e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: None,
};


// 4 :   2, 10,  601,    3, 12,     5,  2,     1, 13,     2, 16,    153, 9.1e-15
pub const PARAM_OPT: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(601),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0517578125e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(16),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(13),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

// - 3 :   2, 10,  672,    3, 12,     4,  3,     1, 13,     2, 16,    163, 7.5e-15
pub const EXP: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(672),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0517578125e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(16),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(13),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

// - 2 :   2, 10,  568,    2, 15,     3,  3,     1, 10,     1, 24,     95, 6.9e-15 | 0 padding bit
pub const EXP2: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(568),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0517578125e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(24),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(10),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

// - 2 :   2, 10,  587,    2, 15,     5,  2,     1, 11,     2, 16,    126, 6.6e-15  | 1 padding bit
pub const EXP3: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(587),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0517578125e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(16),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(11),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};



pub const paper_1: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(549),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0517578125e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(17),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(13),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub fn cpu_params() -> WopbsParameters{
    return EXP2;
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
        FHEParameters::PBS(params) => (
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
    pbs_params: &FHEParameters,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>,
    big_lwe_sk: &LweSecretKey<Vec<u64>>
) -> LweKeyswitchKey<Vec<u64>>
{
    let (ks_base_log, ks_level, lwe_noise_distribution, ciphertext_modulus) = match pbs_params {
        FHEParameters::MultiBit(params) => (
            params.ks_base_log,
            params.ks_level,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
        FHEParameters::Wopbs(params) => (
            params.ks_base_log,
            params.ks_level,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
        FHEParameters::PBS(params) => (
            params.ks_base_log,
            params.ks_level,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
    };
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        ks_base_log,
        ks_level,
        lwe_noise_distribution,
        ciphertext_modulus,
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
        FHEParameters::PBS(params) => (
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

pub fn cpu_gen_pksk
(
    pbs_params: &FHEParameters, 
    input_lwe_secret_key: &LweSecretKey<Vec<u64>>, 
    output_glwe_secret_key: &GlweSecretKey<Vec<u64>>,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> LwePackingKeyswitchKey<Vec<u64>>
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
        FHEParameters::PBS(params) => (
            params.pbs_base_log,
            params.pbs_level,
            params.glwe_noise_distribution,
            params.ciphertext_modulus,
        ),
    };

    let pksk: LwePackingKeyswitchKey<Vec<u64>> = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        pbs_base_log,
        pbs_level,
        glwe_noise_distribution,
        ciphertext_modulus,
        encryption_generator,
    );
    return pksk;
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
    pbs_params: &FHEParameters,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>,
    clear: u64,
    padding: bool,
) -> LweCiphertext<Vec<u64>>
{
    let (plaintext_modulus, lwe_noise_distribution,ciphertext_modulus) = match pbs_params {
        FHEParameters::MultiBit(params) => (
            params.message_modulus.0 * params.carry_modulus.0,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
        FHEParameters::Wopbs(params) => (
            params.message_modulus.0 * params.carry_modulus.0,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
        FHEParameters::PBS(params) => (
            params.message_modulus.0 * params.carry_modulus.0,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
    };


    let mut delta = (1_u64 << 63) / plaintext_modulus;

    if !padding{
        delta *= 2;
    }
    let delta_log = delta.ilog2();
    // println!("delta_log: {}", delta_log);
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

pub fn cpu_encrypt_custom(
    pbs_params: &FHEParameters,
    encryption_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    small_lwe_sk: &LweSecretKey<Vec<u64>>,
    clear: u64,
    delta: u64,
) -> LweCiphertext<Vec<u64>>
{
    let (lwe_noise_distribution,ciphertext_modulus) = match pbs_params {
        FHEParameters::MultiBit(params) => (
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
        FHEParameters::Wopbs(params) => (
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
        FHEParameters::PBS(params) => (
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
        ),
    };

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
    padding: bool
) -> u64
{
    let plaintext_modulus = match pbs_params {
        FHEParameters::MultiBit(params) => params.message_modulus.0 * params.carry_modulus.0,
        FHEParameters::Wopbs(params) => params.message_modulus.0 * params.carry_modulus.0,
        FHEParameters::PBS(params) => params.message_modulus.0 * params.carry_modulus.0,
    };

    let mut delta = (1_u64 << 63) / plaintext_modulus;
    let mut decomp = plaintext_modulus.ilog2() + 1;
    if !padding {
        delta *= 2;
        decomp -= 1;
    }
    
    let dec: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, &ct);
    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(decomp as usize), DecompositionLevelCount(1));
    let dec: u64 = signed_decomposer.closest_representable(dec.0) / delta;

    return dec;
}

pub fn cpu_decrypt_delta
(
    sk: &LweSecretKey<Vec<u64>>,
    ct: &LweCiphertext<Vec<u64>>,
    delta: u64
) -> u64
{

    let decomp = 64 - delta.ilog2();
    let dec: Plaintext<u64> = decrypt_lwe_ciphertext(&sk, &ct);
    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(decomp as usize), DecompositionLevelCount(1));
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

pub fn cpu_lwelist_to_veclwe
(
    lwe_list: &LweCiphertextList<Vec<u64>>,
) -> Vec<LweCiphertext<Vec<u64>>>
{
    let mut vec_lwe_out = Vec::new();
    for lwe_out in lwe_list.iter(){
        let temp = lwe_out.into_container().to_vec();
        vec_lwe_out.push(LweCiphertextOwned::from_container(temp, lwe_out.ciphertext_modulus()));
    }
    return vec_lwe_out;
}

pub fn cpu_modswitch
(
    ct: &mut LweCiphertext<Vec<u64>>,
    new_modulus_log: u64,
)
{
    let (mut mask, body) = ct.get_mut_mask_and_body();
    let mask = mask.as_mut();
    let body = body.data;

    // let output_to_floor = input.wrapping_add(Scalar::ONE << (Scalar::BITS - log_modulus.0 - 1));
    // output_to_floor >> (Scalar::BITS - log_modulus.0)

    *body = body.wrapping_add(u64::ONE << ((u64::BITS as u64) - new_modulus_log - 1));
    *body = *body >> ((u64::BITS as u64) - new_modulus_log);
    for a in mask.iter_mut(){
        *a = a.wrapping_add(u64::ONE << ((u64::BITS as u64) - new_modulus_log - 1));
        *a = *a >> ((u64::BITS as u64) - new_modulus_log);
    }
}