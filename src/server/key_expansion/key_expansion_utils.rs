// use crate::tables::table::SBOX;
use crate::server::sbox::sbox::key_sbox;

use tfhe::{
    shortint::Ciphertext,
    shortint::wopbs::WopbsKey,
    integer::{
        ciphertext::BaseRadixCiphertext,
    }
};

pub const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

pub fn fhe_rot_word(word: &Vec<BaseRadixCiphertext<Ciphertext>>) -> Vec<BaseRadixCiphertext<Ciphertext>> {
    let mut result = Vec::new();
    for i in 0..4 {
        result.push(word[(i + 1) % 4].clone());
    }
    result
}

pub fn fhe_sub_word(wopbs_key: &tfhe::integer::wopbs::WopbsKey, wopbs_key_short: &WopbsKey, word: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    for i in 0..4 {
        let start = std::time::Instant::now();
        key_sbox(wopbs_key, wopbs_key_short, &mut word[i]);
        println!("Sbox: {:?}", start.elapsed());
    }

    // word.par_iter_mut().for_each(|byte| {
    //     sbox(wopbs_key, byte, false);
    // });
}


// fn sub_word(word: u32) -> u32 {
//     let mut result = 0;
//     for i in 0..4 {
//         let byte = ((word >> (8 * (3 - i))) & 0xFF) as u8;
//         result |= (SBOX[byte as usize] as u32) << (8 * (3 - i));
//     }
//     result
// }

// fn rot_word(word: u32) -> u32 {
//     (word << 8) | (word >> 24)
// }

// // For testing purposes only
// pub(crate) fn aes_key_expansion_clear(key: u128) -> Vec<u128> {
//     let nk = 4; // Number of 32-bit words in the key for AES-128
//     let nb = 4; // Number of columns in the fhe_encrypted_state
//     let nr = 10; // Number of rounds for AES-128
//     let mut w = vec![0u32; nb * (nr + 1)]; // Word array to hold expanded keys

//     // Copy the original key into the first `nk` words
//     for i in 0..nk {
//         w[i] = ((key >> (96 - 32 * i)) & 0xFFFFFFFF) as u32;
//     }

//     for i in nk..w.len() {
//         let mut temp = w[i - 1];
//         if i % nk == 0 {
//             temp = sub_word(rot_word(temp)) ^ ((RCON[(i / nk) - 1] as u32) << 24);
//         }
//         w[i] = w[i - nk] ^ temp;
//     }

//     // Combine words into 128-bit round keys
//     let mut round_keys = Vec::with_capacity(nr + 1);
//     for i in 0..=nr {
//         let mut round_key = 0u128;
//         for j in 0..nb {
//             round_key |= (w[nb * i + j] as u128) << (96 - 32 * j);
//         }
//         round_keys.push(round_key);
//     }

//     round_keys
// }