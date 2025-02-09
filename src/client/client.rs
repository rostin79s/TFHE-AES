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

// to generate random test cases
// use rand::Rng;



// Used concrete-optimizer to find paramter-set that gives 128 bit security and 
// failure probability of 6.1e-20 = 2^-64
// log norm2 = 5
// max noise = sqrt(2^5) = 5
// https://github.com/zama-ai/concrete/tree/main/compilers/concrete-optimizer
pub const PARAM_OPT: WopbsParameters =
WopbsParameters {
    lwe_dimension: LweDimension(669),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
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
            max_noise_level: MaxNoiseLevel::new(5),
            log2_p_fail: 1.0,
            ciphertext_modulus: wopbs_params.ciphertext_modulus,
            encryption_key_choice: wopbs_params.encryption_key_choice,
        };

        let shortint_parameters_set = tfhe::shortint::parameters::ShortintParameterSet::try_new_pbs_and_wopbs_param_set((
            pbs_params,
            wopbs_params,
        )).unwrap();
        



        let (cks, sks) = gen_keys_radix(shortint_parameters_set, nb_block);
        let maxnoise = cks.parameters().max_noise_level().get();
        println!("maxnoise: {}", maxnoise);
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

    pub fn client_encrypt(&self) -> (RadixClientKey, PublicKey, ServerKey, WopbsKey, Vec<BaseRadixCiphertext<Ciphertext>>, Vec<BaseRadixCiphertext<Ciphertext>>) {
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


        let public_key = PublicKey::new(&self.cks);

        let test = self.cks.encrypt_without_padding(3 as u64);

        let sag = public_key.encrypt_radix_without_padding(3 as u64, 8);
        let res = self.sks.unchecked_add(&test, &sag);
        let dec: u64 = self.cks.decrypt_without_padding(&res);
        println!("decrypted_sag: {}", dec);

        
    
        (self.cks.clone(), public_key, self.sks.clone(), self.wopbs_key.clone(), encrypted_iv, encrypted_key)
    }

    pub fn client_decrypt_and_verify(&self, index: usize,
        fhe_encrypted_state: &mut Vec<BaseRadixCiphertext<Ciphertext>>
    ){
        let message = self.iv + index as u128;
        println!("message and index: {} , {}", message, index);
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
            // println!("FHE encryption successful. Encrypted message generated: {:032x}", encrypted_message);
        } else {
            println!("Fhe encryption failed ******************************************. Encrypted message generated: {:032x}", encrypted_message);
        }

        // let mut decrypted_message_bytes: Vec<u8> = Vec::new();
        // for fhe_decrypted_byte in fhe_decrypted_state.iter() {
        //     let byte: u128 = self.cks.decrypt_without_padding(fhe_decrypted_byte);
        //     decrypted_message_bytes.push(byte as u8);
        // }

        // let mut decrypted_message: u128 = 0;
        // for (i, &byte) in decrypted_message_bytes.iter().enumerate() {
        //     decrypted_message |= (byte as u128) << ((15 - i) * 8);
        // }

        // if decrypted_message == message {
        //     // println!("FHE decryption successful. Decrypted message: {:032x}", decrypted_message);
        // } else {
        //     println!("Fhe decryption failed ***************************************");
        // }


        
    }

}
