use tfhe::integer::{
    ciphertext::BaseRadixCiphertext, 
    wopbs::WopbsKey,
};

use tfhe::shortint::Ciphertext;

use crate::tables::table::{SBOX, INV_SBOX};
use super::gen_lut::gen_lut;


pub fn sbox(wopbs_key: &WopbsKey, x: &mut BaseRadixCiphertext<Ciphertext>, inv: bool) {
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
    
    let lut = gen_lut(message_mod, carry_mod, poly_size, x, f);

    let ct_res = wopbs_key.wopbs_without_padding(x, &lut);
    // let ct_res2 = wopbs_key.wopbs_without_padding(x, &lut);
    // let ct_res3 = wopbs_key.wopbs_without_padding(x, &lut);
    
    *x = ct_res;

    // println!("Sbox: {:?}", start.elapsed());
}

