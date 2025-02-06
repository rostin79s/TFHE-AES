use core::num;

use tfhe::{
    core_crypto::prelude::generate_lwe_keyswitch_key, integer::{
        ciphertext::BaseRadixCiphertext, gen_keys_radix, wopbs::WopbsKey, RadixClientKey, ServerKey
    }, shortint::{
        parameters::{DynamicDistribution, LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS}, prelude::*, WopbsParameters
        
    }
};

// aes crate library to check if FHE aes encryption works correctly.
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};

// to generate random test cases
// use rand::Rng;


pub const CUSTOM_PARAM: WopbsParameters =
    WopbsParameters {
        lwe_dimension: LweDimension(549),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.0003177104139262535,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        pbs_base_log: DecompositionBaseLog(12),
        pbs_level: DecompositionLevelCount(3),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(2),
        pfks_level: DecompositionLevelCount(2),
        pfks_base_log: DecompositionBaseLog(17),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.162026630747649e-16,
        )),
        cbs_level: DecompositionLevelCount(1),
        cbs_base_log: DecompositionBaseLog(13),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

pub const PARAM_OPT: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(676),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0517578125e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(12),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(2),
    pfks_base_log: DecompositionBaseLog(16),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(13),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub struct Client {
    cks: RadixClientKey,
    sks: ServerKey,
    wopbs_key: WopbsKey,
    number_of_outputs: usize,
    iv: u128,
    key: u128,
}

impl Client {

    pub fn new(_number_of_outputs: usize, _iv: u128, _key: u128) -> Self {
        let nb_block = 8;
        let (cks, sks) = gen_keys_radix(PARAM_OPT, nb_block);
        // let (cks, sks) = gen_keys_radix(LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, nb_block);
        let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

        let number_of_outputs = _number_of_outputs;
        let iv = _iv;
        let key = _key;
        Client {
            cks,
            sks,
            wopbs_key,
            number_of_outputs,
            iv,
            key,
        }
    }

    pub fn client_encrypt(&self) -> (RadixClientKey, ServerKey, WopbsKey, Vec<Vec<BaseRadixCiphertext<Ciphertext>>>, Vec<BaseRadixCiphertext<Ciphertext>>) {

        let mut encrypted_key: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();

        for byte_idx in (0..16).rev() { // 128 bits / 8 bits = 16 bytes
            let byte = (self.key >> (byte_idx * 8)) & 0xFF; // Extract 8 bits
            encrypted_key.push(self.cks.encrypt_without_padding(byte as u64));
        }


        
        // iterate over number_of_outputs and generate encrypted_messages, starting from iv, to iv+number_of_outputs

        let mut encrypted_messages = Vec::new();
        

        for i in 0..self.number_of_outputs {
            let message = self.iv + i as u128;
            let mut encrypted_message: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();
    
            for byte_idx in (0..16).rev() { // 128 bits / 8 bits = 16 bytes
                let byte = (message >> (byte_idx * 8)) & 0xFF; // Extract 8 bits
                encrypted_message.push(self.cks.encrypt_without_padding(byte as u64));
            }
            encrypted_messages.push(encrypted_message);
        }


    
        
    
        (self.cks.clone(), self.sks.clone(), self.wopbs_key.clone(), encrypted_messages, encrypted_key)
    }

    pub fn client_decrypt_and_verify(&self, index: usize,
        fhe_encrypted_state: Vec<BaseRadixCiphertext<Ciphertext>>, fhe_decrypted_state: Vec<BaseRadixCiphertext<Ciphertext>>
    ){
        let message = self.iv + index as u128;
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
        let encrypted_key = self.key.to_be_bytes();
        let mut message_bytes = message.to_be_bytes();
    
        let cipher = Aes128::new(GenericArray::from_slice(&encrypted_key));
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

        if decrypted_message == message {
            println!("FHE decryption successful. Decrypted message: {:032x}", decrypted_message);
        } else {
            println!("Fhe decryption failed. Decrypted message: {:032x}", decrypted_message);
        }


        
    }

}
