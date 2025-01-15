use super::*;

pub fn client_init() -> (ClientKey, ServerKey, Vec<Vec<Ciphertext>>, Vec<Ciphertext>) {
   
    let (cks, sks) = gen_keys(PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64);
    
    // let mut rng = rand::thread_rng();
    // let message: u128 = rng.gen(); // Random 128-bit message
    // let key: u128 = rng.gen();     // Random 128-bit cryptographic key (NOT SECURE)

    let message: u128 = 0x00000101030307070f0f1f1f3f3f7f7f;
    let key = 0;
    
    let round_keys = AES_key_expansion(key);

    for (i, round_key) in round_keys.iter().enumerate() {
        println!("Round {}: {:032x}", i, round_key);
    }

    let message_bits: Vec<bool> = (0..128).map(|i| (message >> i) & 1 == 1).collect();

    let encrypted_message_bits: Vec<Ciphertext> = message_bits
        .iter()
        .map(|&b| cks.encrypt(b as u64))
        .collect();

    let encrypted_round_keys: Vec<Vec<Ciphertext>> = round_keys
    .iter()
    .map(|&round_key| {
        (0..128)
            .map(|i| (round_key >> i) & 1 == 1)
            .map(|b| cks.encrypt(b as u64))
            .collect()
    })
    .collect();

    (cks, sks, encrypted_round_keys, encrypted_message_bits)
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

pub fn AES_key_expansion(key: u128) -> Vec<u128> {
    let nk = 4; // Number of 32-bit words in the key for AES-128
    let nb = 4; // Number of columns in the state
    let nr = 10; // Number of rounds for AES-128
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

// pub fn encrypted_aes_key_expansion(cks: &ClientKey, encrypted_key_bits: &Vec<Ciphertext>) -> Vec<Vec<Ciphertext>> {
    
// }

