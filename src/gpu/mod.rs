pub mod key_switch;
pub mod pbs;
pub mod extract_bits;
pub mod cbs_vp;


use tfhe::{
    shortint::{
        prelude::{
            LweDimension
        }
    },
    core_crypto::{
        prelude::{
            LweKeyswitchKey,
            LweCiphertext,
            LweCiphertextList,
            LweSize,
            LweCiphertextCount,
            keyswitch_lwe_ciphertext
        },
        gpu::{
            CudaStreams,
            vec::{
                CudaVec,
                GpuIndex
            },
            lwe_ciphertext_list::CudaLweCiphertextList,
            lwe_keyswitch_key::CudaLweKeyswitchKey,
            cuda_keyswitch_lwe_ciphertext,
            convert_lwe_keyswitch_key_async,

        },
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
