use tfhe::integer::wopbs::IntegerWopbsLUT;

use tfhe::{
    integer::ciphertext::BaseRadixCiphertext,
    shortint::{
        wopbs::WopbsKey,
        Ciphertext
    }
};

use crate::tables::table::{SBOX, INV_SBOX};
use super::gen_lut::gen_lut;
use super::many_wopbs::many_wopbs_without_padding;




// formula for multiplication by 2 in GF(2^8)
pub fn mul2(x: u8) -> u8 {
    let mut y = x << 1;
    if (x & 0x80) != 0 { 
        y ^= 0x1B;       
    }
    y & 0xFF 
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


// Sbox evaluation used in Key Expansion using wopbs.
pub fn sbox(wopbs_key: &tfhe::integer::wopbs::WopbsKey, wopbs_key_short: &tfhe::shortint::wopbs::WopbsKey, ct_in: &mut BaseRadixCiphertext<Ciphertext>){
    let f = |x| SBOX[x as usize] as u64;
    let lut = gen_lut(
        wopbs_key_short.param.message_modulus.0 as usize,
        wopbs_key_short.param.carry_modulus.0 as usize,
        wopbs_key_short.param.polynomial_size.0,
        8,
        f,
    );
    let ct_res = wopbs_key.wopbs_without_padding(ct_in, &lut);
    *ct_in = ct_res;
}

// We embed the mul(x) functions in the sbox function, that are used in the subsequent mix columns operation in both 
// AES encryption and decryption. We sperate the circuit bootstrapping functionality from the vertical packing, and we comute
// multiple look up tables with different vertical packings, which is almost free compared to the cost of the circuit bootstrapping.
pub fn many_sbox(wopbs_key_short: &WopbsKey, ct_in: &mut BaseRadixCiphertext<Ciphertext>, inv: bool) -> Vec<BaseRadixCiphertext<Ciphertext>> {

    let mut functions: Vec<fn(u64) -> u64> = vec![];
    let mut luts: Vec<IntegerWopbsLUT> = vec![];

    if inv {
        functions.push(|x| mul9(INV_SBOX[x as usize] as u8) as u64);
        functions.push(|x| mul11(INV_SBOX[x as usize] as u8) as u64);
        functions.push(|x| mul13(INV_SBOX[x as usize] as u8) as u64);
        functions.push(|x| mul14(INV_SBOX[x as usize] as u8) as u64);
    } else {
        functions.push(|x| SBOX[x as usize] as u64);
        functions.push(|x| mul2(SBOX[x as usize] as u8) as u64);
        functions.push(|x| mul3(SBOX[x as usize] as u8) as u64);
    }


    for f in functions.iter() {
        let lut = gen_lut(
            wopbs_key_short.param.message_modulus.0 as usize,
            wopbs_key_short.param.carry_modulus.0 as usize,
            wopbs_key_short.param.polynomial_size.0,
            8,
            *f,
        );
        luts.push(lut);
    }
    let out_list = many_wopbs_without_padding(ct_in, wopbs_key_short, luts);
    return out_list;
}