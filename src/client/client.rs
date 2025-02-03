use tfhe::integer::{RadixClientKey, ServerKey};

use super::*;

use crate::server::sbox::sbox;

use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};

pub struct Client {
    cks: RadixClientKey,
    sks: ServerKey,
    wopbs_key: WopbsKey,
    message: u128,
    key: u128,
}

impl Client {
    pub fn new() -> Self {
        // Initialize FHE keys
        let nb_block = 8;
        let (cks, sks) = gen_keys_radix(WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, nb_block);

        let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

        
        // let message: u128 = 0x00112233445566778899aabbccddeeff;
        // let key: u128 = 0x000102030405060708090a0b0c0d0e0f;


        let message: u128 = 0x00000101030307070f0f1f1f3f3f7f7f;
        let key: u128 = 0;

        Client {
            cks,
            sks,
            wopbs_key,
            message,
            key,
        }
    }

    pub fn client_encrypt(&self) -> (RadixClientKey, ServerKey, WopbsKey, Vec<BaseRadixCiphertext<Ciphertext>>, Vec<Vec<BaseRadixCiphertext<Ciphertext>>>) {

    
        let round_keys = aes_key_expansion(self.key);
    
        // for (i, round_key) in round_keys.iter().enumerate() {
        //     println!("Round {}: {:032x}", i, round_key);
        // }

        let mut key_bytes: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();

        for byte_idx in (0..16).rev() { // 128 bits / 8 bits = 16 bytes
            let byte = (self.key >> (byte_idx * 8)) & 0xFF; // Extract 8 bits
            key_bytes.push(self.cks.encrypt_without_padding(byte as u64));
        }

        let _encrypted_round_keys: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = key_expansion(&self.cks, &self.sks, &self.wopbs_key, &key_bytes);

        let length = _encrypted_round_keys.len();
        println!("Length: {:?}", length);
        
        for (i, encrypted_round_key) in _encrypted_round_keys.iter().enumerate() {
            let mut decrypted_round_key: u128 = 0;
            for (j, encrypted_byte) in encrypted_round_key.iter().enumerate() {
                let decrypted_byte: u128 = self.cks.decrypt_without_padding(encrypted_byte); // Decrypt as an 8-bit integer
                println!("Decrypted byte: {:?}", decrypted_byte);
                let position = (15 - j) * 8; // Compute bit position from MSB
                decrypted_round_key |= (decrypted_byte as u128) << position; // Store in the correct position
            }
            println!("Round {}: {:032x}", i, decrypted_round_key);
            assert_eq!(decrypted_round_key, round_keys[i], "Round key mismatch at index {}", i);
        }
        

    
        let mut encrypted_bytes: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();
    
        for byte_idx in (0..16).rev() { // 128 bits / 8 bits = 16 bytes
            let byte = (self.message >> (byte_idx * 8)) & 0xFF; // Extract 8 bits
            encrypted_bytes.push(self.cks.encrypt_without_padding(byte as u64));
        }
    
        let encrypted_round_keys: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = round_keys
        .iter()
        .map(|&round_key| {
            (0..16) // 128 bits divided into 16 bytes
                .rev() // Process from MSB to LSB
                .map(|byte_idx| {
                    let byte = (round_key >> (byte_idx * 8)) & 0xFF; // Extract 8-bit chunk
                    self.cks.encrypt_without_padding(byte as u64) // Encrypt as a single 8-bit integer
                })
                .collect()
        })
        .collect();
    
        (self.cks.clone(), self.sks.clone(), self.wopbs_key.clone(), encrypted_bytes, encrypted_round_keys)
    }

    pub fn client_decrypt_and_verify(&self,
        fhe_encrypted_state: Vec<BaseRadixCiphertext<Ciphertext>>, fhe_decrypted_state: Vec<BaseRadixCiphertext<Ciphertext>>
    ) {
        // Decrypt the message
        let mut encrypted_message_bytes: Vec<u8> = Vec::new();
        for fhe_encrypted_byte in fhe_encrypted_state.iter() {
            let encrypted_byte: u128 = self.cks.decrypt_without_padding(fhe_encrypted_byte);
            encrypted_message_bytes.push(encrypted_byte as u8);
        }
    
        // Convert decrypted bytes to u128
        let mut encrypted_message: u128 = 0;
        for (i, &byte) in encrypted_message_bytes.iter().enumerate() {
            encrypted_message |= (byte as u128) << ((15 - i) * 8);
        }

        
        // Encrypt the message using AES for verification
        let key_bytes = self.key.to_be_bytes();
        let mut message_bytes = self.message.to_be_bytes();
    
        let cipher = Aes128::new(GenericArray::from_slice(&key_bytes));
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut message_bytes));
    
        let clear_encrypted_message = u128::from_be_bytes(message_bytes);
    
        // Verify the decrypted message
        if encrypted_message == clear_encrypted_message {
            println!("FHE encryption successful. Encrypted message generated: {:032x}", encrypted_message);
        } else {
            println!("Fhe encryption failed. Encrypted message generated: {:032x}", encrypted_message);
        }

        let mut decrypted_message_bytes: Vec<u8> = Vec::new();
        for fhe_decrypted_byte in fhe_decrypted_state.iter() {
            let byte: u128 = self.cks.decrypt_without_padding(fhe_decrypted_byte);
            decrypted_message_bytes.push(byte as u8);
        }

        let mut decrypted_message: u128 = 0;
        for (i, &byte) in decrypted_message_bytes.iter().enumerate() {
            decrypted_message |= (byte as u128) << ((15 - i) * 8);
        }

        if decrypted_message == self.message {
            println!("FHE decryption successful. Decrypted message: {:032x}", decrypted_message);
        } else {
            println!("Fhe decryption failed. Decrypted message: {:032x}", decrypted_message);
        }

        
    }

}





const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

fn sub_word(word: u32) -> u32 {
    let mut result = 0;
    for i in 0..4 {
        let byte = ((word >> (8 * (3 - i))) & 0xFF) as u8;
        result |= (table::SBOX[byte as usize] as u32) << (8 * (3 - i));
    }
    result
}

fn rot_word(word: u32) -> u32 {
    (word << 8) | (word >> 24)
}

fn fhe_rot_word(word: &Vec<BaseRadixCiphertext<Ciphertext>>) -> Vec<BaseRadixCiphertext<Ciphertext>> {
    let mut result = Vec::new();
    for i in 0..4 {
        result.push(word[(i + 1) % 4].clone());
    }
    result
}

fn fhe_sub_word(wopbs_key: &WopbsKey, word: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    for i in 0..4 {
        sbox(wopbs_key, &mut word[i], false);
    }
}

pub fn key_expansion(cks: &RadixClientKey, sks: &ServerKey, wopbs_key: &WopbsKey, key: &Vec<BaseRadixCiphertext<Ciphertext>>) -> Vec<Vec<BaseRadixCiphertext<Ciphertext>>> {
    let nk = 4; // Number of 32-bit words in the key for AES-128
    let nb = 4; // Number of columns in the fhe_encrypted_state
    let nr = 4; // Number of rounds for AES-128
    let mut w = Vec::new(); // Word array to hold expanded keys

    // Copy the original key into the first `nk` words
    for i in 0..nk {
        let mut word = Vec::new();
        for j in 0..4 {
            word.push(key[4 * i + j].clone());
        }
        w.push(word);
    }

    for i in nk..nb * (nr + 1) {
        let mut temp = w[i - 1].clone();
        if i % nk == 0 {
            temp = fhe_rot_word(&temp);
            // decrypt and print temp
            for j in 0..4 {
                let decrypted_byte: u64 = cks.decrypt_without_padding(&temp[j]);
                println!("Decrypted byte after rotate: {:?}", decrypted_byte);
            }
            fhe_sub_word(wopbs_key, &mut temp);
            // decrypt and print temp
            for j in 0..4 {
                let decrypted_byte: u64 = cks.decrypt_without_padding(&temp[j]);
                println!("Decrypted byte: {:?}", decrypted_byte);
            }
            let rcon_byte= RCON[(i / nk) - 1] as u64;
            println!("Rcon: {:?}", rcon_byte);
            let encrypted_rcon = cks.encrypt_without_padding(rcon_byte as u64);
            temp[0] = sks.unchecked_add(&temp[0], &encrypted_rcon);
            // decrypt and print temp
            for j in 0..4 {
                let decrypted_byte: u64 = cks.decrypt_without_padding(&temp[j]);
                println!("Decrypted byte after rcon: {:?}", decrypted_byte);
            }
        }
        let mut new_word = Vec::new();
        for j in 0..4 {
            let sag = sks.unchecked_add(&w[i - nk][j], &temp[j]);
            // print sag
            let decrypted_byte: u64 = cks.decrypt_without_padding(&sag);
            println!("Decrypted byte after add: {:?}", decrypted_byte);
            new_word.push(sag);
        }
        w.push(new_word);
    }

    // Combine every 4 words into a single round key
    let mut round_keys = Vec::new();
    for i in 0..=nr {
        let mut round_key = Vec::new();
        for j in 0..4 {
            round_key.extend(w[i * 4 + j].clone());
        }
        round_keys.push(round_key);
    }

    round_keys
}


pub fn aes_key_expansion(key: u128) -> Vec<u128> {
    let nk = 4; // Number of 32-bit words in the key for AES-128
    let nb = 4; // Number of columns in the fhe_encrypted_state
    let nr = 4; // Number of rounds for AES-128
    let mut w = vec![0u32; nb * (nr + 1)]; // Word array to hold expanded keys

    // Copy the original key into the first `nk` words
    for i in 0..nk {
        w[i] = ((key >> (96 - 32 * i)) & 0xFFFFFFFF) as u32;
    }

    for i in nk..w.len() {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ ((RCON[(i / nk) - 1] as u32) << 24);
        }
        w[i] = w[i - nk] ^ temp;
    }

    // Combine words into 128-bit round keys
    let mut round_keys = Vec::with_capacity(nr + 1);
    for i in 0..=nr {
        let mut round_key = 0u128;
        for j in 0..nb {
            round_key |= (w[nb * i + j] as u128) << (96 - 32 * j);
        }
        round_keys.push(round_key);
    }

    round_keys
}

