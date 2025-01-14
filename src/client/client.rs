use super::*;

pub fn client_init() -> (ClientKey, ServerKey, Vec<Ciphertext>, Vec<Ciphertext>) {
   
    let (cks, sks) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);
    let mut rng = rand::thread_rng();
    let message: u128 = rng.gen(); // Random 128-bit message
    let key: u128 = rng.gen();     // Random 128-bit cryptographic key (NOT SECURE)
    

    let message_bits: Vec<bool> = (0..128).map(|i| (message >> i) & 1 == 1).collect();
    let key_bits: Vec<bool> = (0..128).map(|i| (key >> i) & 1 == 1).collect();

    let encrypted_message_bits: Vec<Ciphertext> = message_bits
        .iter()
        .map(|&b| cks.encrypt(b as u64))
        .collect();

    let encrypted_key_bits: Vec<Ciphertext> = key_bits
        .iter()
        .map(|&b| cks.encrypt(b as u64))
        .collect();

    return (cks, sks, encrypted_message_bits, encrypted_key_bits);
    
}

// pub fn encrypted_aes_key_expansion(cks: &ClientKey, encrypted_key_bits: &Vec<Ciphertext>) -> Vec<Vec<Ciphertext>> {
    
// }

