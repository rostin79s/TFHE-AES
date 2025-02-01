use super::{table::SBOX, *};

use tfhe::integer::{IntegerCiphertext, 
    wopbs::{IntegerWopbsLUT, PlaintextCount, CiphertextCount}

};


pub fn sbox(wopbs_key: &WopbsKey, x: &mut BaseRadixCiphertext<Ciphertext>) {
    let message_mod = 2;
    let carry_mod = 1;

    let poly_size = 512;
    let f = |x| SBOX[x as usize] as u64;

    let start = std::time::Instant::now();
    
    let lut = gen_lut(message_mod, carry_mod, poly_size, x, f);

    let ct_res = wopbs_key.wopbs_without_padding(x, &lut);
    *x = ct_res;

    println!("Sbox: {:?}", start.elapsed());
}



fn gen_lut<F, T>(message_mod: usize, carry_mod: usize, poly_size: usize, ct: &T, f: F) -> IntegerWopbsLUT 
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
            // find the value represented by the index
            let mut value = 0;
            let mut tmp_index = index;
            for i in 0..nb_block as u64 {
                let tmp = tmp_index % (1 << log_basis); // Extract only the relevant block
                tmp_index >>= log_basis; // Move to the next block
                value += tmp << (log_message_modulus * i); // Properly reconstruct `value`
            }

            // fill the LUTs
            for block_index in 0..nb_block {
                let masked_value = (f(value as u64) >> (log_message_modulus * block_index as u64))
                    % (1 << log_message_modulus);  // Mask the value using the message modulus
            
                lut[block_index][index] = masked_value << delta;  // Apply delta to the LUT entry
            }
        }
        lut
    }

