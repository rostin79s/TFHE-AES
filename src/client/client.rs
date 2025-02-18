use tfhe::{
    integer::{
        ciphertext::BaseRadixCiphertext,
        gen_keys_radix,
        wopbs::WopbsKey,
        RadixClientKey,
        ServerKey,
        PublicKey
    }, shortint::{
        parameters::DynamicDistribution,
        prelude::*,
        WopbsParameters
        
    }
};

// aes crate library to check if FHE aes encryption works correctly.
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};



// Used concrete-optimizer to find paramter-set that gives 128 bit security and 
// failure probability of 6.1e-20 = 2^-64
// log norm2 = 5
// max noise = sqrt(2^5) = 5
// https://github.com/zama-ai/concrete/tree/main/compilers/concrete-optimizer
pub const PARAM_OPT: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(669),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0517578125e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(5),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(3),
    pfks_base_log: DecompositionBaseLog(12),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(15),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const paper: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(549),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
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

pub const cheap: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(588),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0003177104139262535,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(24),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    cbs_level: DecompositionLevelCount(1),
    cbs_base_log: DecompositionBaseLog(10),
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
    // Initialize client with number of outputs, iv and key, and generate wopbs paramters and keys.
    pub fn new(_number_of_outputs: usize, _iv: u128, _key: u128) -> Self {
        let nb_block = 8;

        let parameters_set = PARAM_OPT;

        let shortint_parameters_set: tfhe::shortint::parameters::ShortintParameterSet =
        parameters_set.try_into().unwrap();
 
        
        let wopbs_params = shortint_parameters_set.wopbs_parameters().unwrap();
        let pbs_params = tfhe::shortint::parameters::ClassicPBSParameters {
            lwe_dimension: wopbs_params.lwe_dimension,
            glwe_dimension: wopbs_params.glwe_dimension,
            polynomial_size: wopbs_params.polynomial_size,
            lwe_noise_distribution: wopbs_params.lwe_noise_distribution,
            glwe_noise_distribution: wopbs_params.glwe_noise_distribution,
            pbs_base_log: wopbs_params.pbs_base_log,
            pbs_level: wopbs_params.pbs_level,
            ks_base_log: wopbs_params.ks_base_log,
            ks_level: wopbs_params.ks_level,
            message_modulus: wopbs_params.message_modulus,
            carry_modulus: wopbs_params.carry_modulus,
            max_noise_level: MaxNoiseLevel::new(5), // Computed from log norm2
            log2_p_fail: 1.0,
            ciphertext_modulus: wopbs_params.ciphertext_modulus,
            encryption_key_choice: wopbs_params.encryption_key_choice,
        };

        let shortint_parameters_set = tfhe::shortint::parameters::ShortintParameterSet::try_new_pbs_and_wopbs_param_set((
            pbs_params,
            wopbs_params,
        )).unwrap();
        



        let (cks, sks) = gen_keys_radix(shortint_parameters_set, nb_block);
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

    // Encrypt key and iv using FHE and return the encrypted key and iv.
    pub fn client_encrypt(&self) -> (PublicKey, ServerKey, WopbsKey, Vec<BaseRadixCiphertext<Ciphertext>>, Vec<BaseRadixCiphertext<Ciphertext>>) {
        // Client encrypts key and sends to server.
        let mut encrypted_key: Vec<BaseRadixCiphertext<Ciphertext>> = Vec::new();
        for byte_idx in (0..16).rev() { 
            let byte = (self.key >> (byte_idx * 8)) & 0xFF;
            encrypted_key.push(self.cks.encrypt_without_padding(byte as u64));
        }


        
        // Client encrypts iv and sends to server.
        let mut encrypted_iv = Vec::new();
        for byte_idx in (0..16).rev() {
            let byte = (self.iv >> (byte_idx * 8)) & 0xFF;
            encrypted_iv.push(self.cks.encrypt_without_padding(byte as u64));
        }

        // for encrypting constants server side
        let public_key = PublicKey::new(&self.cks);
    
        (public_key, self.sks.clone(), self.wopbs_key.clone(), encrypted_iv, encrypted_key)
    }

    // Decrypt FHE AES CTR encryption and verify correctness using aes crate.
    pub fn client_decrypt_and_verify(&self, vec_fhe_encrypted_state: &mut Vec<Vec<BaseRadixCiphertext<Ciphertext>>>
    ){
        assert!(vec_fhe_encrypted_state.len() == self.number_of_outputs);
        for (index, fhe_encrypted_state) in vec_fhe_encrypted_state.iter().enumerate() {
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

            assert_eq!(encrypted_message, clear_encrypted_message);            
            
        }
        
    }

    // Verify correctness of all FHE computations in test function in main.rs
    pub fn test_verify(&self, state_enc: &Vec<BaseRadixCiphertext<Ciphertext>>, state_dec: &Vec<BaseRadixCiphertext<Ciphertext>>) {
        // Test FHE AES encryption
        let message = self.iv;
        let mut encrypted_message_bytes: Vec<u8> = Vec::new();
        for fhe_encrypted_byte in state_enc.iter() {
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

        assert_eq!(encrypted_message, clear_encrypted_message);

        // Test FHE AES decryption
        let mut decrypted_message_bytes: Vec<u8> = Vec::new();
        for fhe_decrypted_byte in state_dec.iter() {
            let byte: u128 = self.cks.decrypt_without_padding(fhe_decrypted_byte);
            decrypted_message_bytes.push(byte as u8);
        }

        let mut decrypted_message: u128 = 0;
        for (i, &byte) in decrypted_message_bytes.iter().enumerate() {
            decrypted_message |= (byte as u128) << ((15 - i) * 8);
        }

        assert_eq!(decrypted_message, message);
        println!("Passed test case.");
    }

}
