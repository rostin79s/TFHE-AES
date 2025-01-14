use super::*;

pub fn client_init() -> (ClientKey, ServerKey, Vec<Ciphertext>, Vec<Ciphertext>) {
   
    let (cks, sks) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);
    let mut rng = rand::thread_rng();
    let message: u128 = rng.gen(); // Random 128-bit message
    let key: u128 = rng.gen();     // Random 128-bit cryptographic key (NOT SECURE)
    
    let round_keys = AES_key_expansion(key);

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

pub fn AES_key_expansion(key: u128) -> Vec<u128> {
    const RCON: [u8; 10] = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    ];

    let mut round_keys = Vec::new();
    let mut key_schedule = [0u8; 16];

    // Fill the key schedule with the original 128-bit key
    for i in 0..16 {
        key_schedule[i] = (key >> (120 - 8 * i)) as u8;
    }
    round_keys.push(u128::from_le_bytes(key_schedule));

    // Key expansion loop (for 10 rounds, generating 44 4-byte words)
    for i in 1..11 {
        let mut temp = key_schedule[12..16].to_vec();
        
        // Rotate and substitute the last 4 bytes
        temp.rotate_left(1);
        for byte in temp.iter_mut() {
            *byte = table::SBOX[*byte as usize];
        }

        // Apply RCON to the first byte
        temp[0] ^= RCON[i - 1];

        // Generate the next key word by XORing the previous word with the expanded word
        for j in 0..4 {
            key_schedule[4 * i + j] = key_schedule[4 * (i - 1) + j] ^ temp[j];
        }

        // Add the newly expanded word to the round key list
        round_keys.push(u128::from_le_bytes(key_schedule[4 * i..4 * (i + 1)].try_into().unwrap()));

        println!("Round {}: {:x}", i, round_keys[i]);
    }

    round_keys
}

// pub fn encrypted_aes_key_expansion(cks: &ClientKey, encrypted_key_bits: &Vec<Ciphertext>) -> Vec<Vec<Ciphertext>> {
    
// }

