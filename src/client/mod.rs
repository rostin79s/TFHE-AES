// use tfhe::shortint::parameters::p_fail_2_minus_64::ks_pbs::*;
// use tfhe::shortint::prelude::*;

// use rand::Rng; // For generating random numbers.

pub mod client;

pub use client::*;

pub use crate::tables::table;

use tfhe::{
    integer::{
        gen_keys_radix, wopbs::*
    },
    shortint::parameters::WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    shortint::ciphertext::Ciphertext
};

use tfhe::integer::ciphertext::BaseRadixCiphertext;