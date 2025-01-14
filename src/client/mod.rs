use tfhe::shortint::parameters::p_fail_2_minus_64::ks_pbs::*;
use tfhe::shortint::prelude::*;

use rand::Rng; // For generating random numbers.

pub mod client;

pub use client::*;