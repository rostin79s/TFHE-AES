use super::*;

pub fn aes_key_expansion(key: u128) -> Vec<u128> {
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
            *byte = SBOX[*byte as usize];
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