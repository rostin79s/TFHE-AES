use crate::server::sbox::sbox::sbox;

use tfhe::{
    shortint::Ciphertext,
    shortint::wopbs::WopbsKey,
    integer::ciphertext::BaseRadixCiphertext,
};

// RCON is used in the key expansion process
pub const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

// We rotate the vector of 4 words by 1 position to the left
pub fn fhe_rot_word(word: &Vec<BaseRadixCiphertext<Ciphertext>>) -> Vec<BaseRadixCiphertext<Ciphertext>> {
    let mut result = Vec::new();
    for i in 0..4 {
        result.push(word[(i + 1) % 4].clone());
    }
    result
}

// We apply the SBOX to each byte of the word
pub fn fhe_sub_word(wopbs_key: &tfhe::integer::wopbs::WopbsKey, wopbs_key_short: &WopbsKey, word: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    for i in 0..4 {
        sbox(wopbs_key, wopbs_key_short, &mut word[i], false);
    }
}