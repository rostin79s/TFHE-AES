
use tfhe::integer::{
    IntegerCiphertext,
    wopbs::{
        IntegerWopbsLUT,
        PlaintextCount, 
        CiphertextCount
    }
};

pub fn gen_lut<F, T>(message_mod: usize, carry_mod: usize, poly_size: usize, ct: &T, f: F) -> IntegerWopbsLUT 
    where
        F: Fn(u64) -> u64,
        T: IntegerCiphertext,
    {
        let log_message_modulus =
            f64::log2((message_mod) as f64) as u64;
        let log_carry_modulus = f64::log2((carry_mod) as f64) as u64;
        let log_basis = log_message_modulus + log_carry_modulus;
        let delta = 64 - log_basis;
        let nb_block = ct.blocks().len();
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
                let masked_value = (f(value as u64) >> (log_message_modulus * block_index as u64))
                    % (1 << log_message_modulus); 
            
                lut[block_index][index] = masked_value << delta; 
            }
        }
        lut
    }