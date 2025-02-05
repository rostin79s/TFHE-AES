use tfhe::{
    integer::{
        RadixClientKey,
        ServerKey,
        gen_keys_radix,
        wopbs::WopbsKey,
        ciphertext::BaseRadixCiphertext
    },
    shortint::{
        prelude::*,
        parameters::DynamicDistribution,
        WopbsParameters,
        
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

pub struct Client {
    cks: RadixClientKey,
    sks: ServerKey,
    wopbs_key: WopbsKey,
    message: u128,
    key: u128,
}


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

impl Client {

    pub fn new() -> Self {
        let nb_block = 8;
        let (cks, sks) = gen_keys_radix(CUSTOM_PARAM, nb_block);

        let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

        // let mut rng = rand::thread_rng();
        // let message: u128 = rng.gen();
        // let key: u128 = rng.gen();
        
        let message: u128 = 0x00112233445566778841aabbccddeeff;
        let key: u128 = 0x000102030405230708090a0b0c0d0e0f;

        Client {
            cks,
            sks,
            wopbs_key,
            message,
            key,
        }
    }

    pub fn client_encrypt(&self) -> (RadixClientKey, ServerKey, WopbsKey, Vec<BaseRadixCiphertext<Ciphertext>>, Vec<BaseRadixCiphertext<Ciphertext>>) {

        let mut encrypted_key: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();

        for byte_idx in (0..16).rev() { // 128 bits / 8 bits = 16 bytes
            let byte = (self.key >> (byte_idx * 8)) & 0xFF; // Extract 8 bits
            encrypted_key.push(self.cks.encrypt_without_padding(byte as u64));
        }


        

    
        let mut encrypted_message: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();
    
        for byte_idx in (0..16).rev() { // 128 bits / 8 bits = 16 bytes
            let byte = (self.message >> (byte_idx * 8)) & 0xFF; // Extract 8 bits
            encrypted_message.push(self.cks.encrypt_without_padding(byte as u64));
        }
    
        (self.cks.clone(), self.sks.clone(), self.wopbs_key.clone(), encrypted_message, encrypted_key)
    }

    pub fn client_decrypt_and_verify(&self,
        fhe_encrypted_state: Vec<BaseRadixCiphertext<Ciphertext>>, fhe_decrypted_state: Vec<BaseRadixCiphertext<Ciphertext>>
    ) -> bool {
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
        let encrypted_key = self.key.to_be_bytes();
        let mut message_bytes = self.message.to_be_bytes();
    
        let cipher = Aes128::new(GenericArray::from_slice(&encrypted_key));
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut message_bytes));
    
        let clear_encrypted_message = u128::from_be_bytes(message_bytes);
    
        // Verify the decrypted message
        if encrypted_message == clear_encrypted_message {
            println!("FHE encryption successful. Encrypted message generated: {:032x}", encrypted_message);
        } else {
            println!("Fhe encryption failed. Encrypted message generated: {:032x}", encrypted_message);
            return false;
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
            return false;
        }

        return true;

        
    }

}
