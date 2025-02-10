use tfhe::{
    integer::{
        ciphertext::BaseRadixCiphertext,
        wopbs::WopbsKey,
        IntegerCiphertext,
        PublicKey,
        ServerKey
    },
    shortint::Ciphertext,
};

use super::sbox::{
    sbox::{sbox,many_sbox},
    many_wopbs::many_wopbs_without_padding,
    gen_lut::gen_lut
};
use super::encrypt::mix_columns;
use super::encrypt::shift_rows;

use super::decrypt::inv_mix_columns;
use super::decrypt::inv_shift_rows;
use super::key_expansion::key_expansion_utils::{RCON, fhe_rot_word, fhe_sub_word};

pub struct Server {
    public_key: PublicKey,
    sks: ServerKey,
    wopbs_key: WopbsKey,
    wopbs_key_short: tfhe::shortint::wopbs::WopbsKey,
}

impl Server {
    pub fn new(public_key: PublicKey, sks: ServerKey, wopbs_key: WopbsKey) -> Self {
        let wopbs_key_short = wopbs_key.clone().into_raw_parts();
        Server {public_key, sks, wopbs_key, wopbs_key_short }
    }

    // AES encryption. We use wopbs_without_padding to compute SBOX, and use many_wopbs_without_padding to compute many 
    // lookups to reduce max noise level required (additions between wopbs).
    pub fn aes_encrypt(&self, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>> , state: &mut Vec<BaseRadixCiphertext<Ciphertext>>){

        let rounds = 10;
        add_round_key(&self.sks,  state, &encrypted_round_keys[0]);

        for round in 1..rounds {
            // we apply many sbox function, which embeds the mul functions in the sbox function, to compute mul2 and mul3 in one go with the cost of one CBS. This computes 3 LUTs, one normal SBOX LUT and one mul2(SBOX) LUT and one mul3(SBOX) LUT, and store the resulting ciphertext in a vector in respective order.
            let mut mul_sbox_state: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = Vec::new();
            for byte_ct in state.iter_mut() {
                let mul_sbox_byte = many_sbox(&self.wopbs_key_short, byte_ct, false);
                mul_sbox_state.push(mul_sbox_byte);
            }

            // now we apply mix columns (first we do shift rows inside), using the mul resuts stored in mul_sbox_state.
            let mut new_state = mix_columns(&self.sks, &mut mul_sbox_state);
            add_round_key(&self.sks, &mut new_state, &encrypted_round_keys[round]);
            *state = new_state;
        }

        // We do normal sbox since there is no mix columns after.
        for byte_ct in state.iter_mut() {
            sbox(&self.wopbs_key, &self.wopbs_key_short, byte_ct, false);
        }
        shift_rows(state);
        add_round_key(&self.sks, state, &encrypted_round_keys[rounds]);
    }

    // Same techniques used as AES encryption. 
    pub fn aes_decrypt(&self, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>>, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>){
        let rounds = 10;

        add_round_key(&self.sks, state, &encrypted_round_keys[rounds]);

        for round in (2..=rounds).rev() {
            inv_shift_rows(state);

            // We do normal sbox
            for byte_ct in state.iter_mut() {
                sbox(&self.wopbs_key, &self.wopbs_key_short, byte_ct, true);
            }
            

            add_round_key(&self.sks, state, &encrypted_round_keys[round - 1]);

            // we apply many_sbox function, but without the sbox part, to compute mul9, mul11, mul13 and 
            // mul14 (stored in order) to reduce the additions, which reduces the max noise level required.
            // This unfortunately almost doubles execution time compared to AES encryption,
            // to guarantee correctness.
            let mut mul_sbox_state: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = Vec::new();
            for byte_ct in state.iter_mut() {
                let mul_sbox_byte = many_sbox(&self.wopbs_key_short, byte_ct, true);
                mul_sbox_state.push(mul_sbox_byte);
            }

            // now we apply inv mix columns using the mul results stored in mul_sbox_state.
            let new_state = inv_mix_columns(&self.sks, &mut mul_sbox_state);
            *state = new_state;
        }

        inv_shift_rows(state);

        for byte_ct in state.iter_mut() {
            sbox(&self.wopbs_key, &self.wopbs_key_short, byte_ct, true);
        }

        add_round_key(&self.sks, state, &encrypted_round_keys[0]);
    }

    pub fn aes_key_expansion(&self, key: &Vec<BaseRadixCiphertext<Ciphertext>>) -> Vec<Vec<BaseRadixCiphertext<Ciphertext>>> {
        let nk = 4; // Number of 32-bit words in the key for AES-128
        let nb = 4; // Number of columns in the state
        let nr = 10; // Number of rounds for AES-128
        let mut w = Vec::new(); // Word array to hold expanded keys
    
        let message_mod = self.wopbs_key_short.param.message_modulus.0 as usize;
        let carry_mod = self.wopbs_key_short.param.carry_modulus.0 as usize;
        let poly_size = self.wopbs_key_short.param.polynomial_size.0;

        // We use this to refresh the noise level to 1 for each round key byte generated
        let f = |x| x as u64;
        let lut = gen_lut(message_mod, carry_mod, poly_size, 8, f);
    
        // Copy the original key into the first `nk` words
        for i in 0..nk {
            let mut word = Vec::new();
            for j in 0..4 {
                word.push(key[4 * i + j].clone());
            }
            w.push(word);
        }
    
        // Key expansion algorithm
        for i in nk..nb * (nr + 1) {
            let mut temp = w[i - 1].clone();
            if i % nk == 0 {
                // We rotate word temp and apply sbox
                temp = fhe_rot_word(&temp);
                fhe_sub_word(&self.wopbs_key, &self.wopbs_key_short, &mut temp);

                // We encrypt RCON using public key
                let rcon_byte= RCON[(i / nk) - 1] as u64;
                let encrypted_rcon = &self.public_key.encrypt_radix_without_padding(rcon_byte as u64, 8);

                // We add the rcon byte to the first byte of temp
                temp[0] = self.sks.unchecked_add(&temp[0], &encrypted_rcon);
            }
            let mut new_words = Vec::new();
            // we generate new words for round keys
            for j in 0..4 {
                let new_word = &self.sks.unchecked_add(&w[i - nk][j], &temp[j]);
                // we refresh the noise level to 1
                let refresh_ct = self.wopbs_key.wopbs_without_padding(new_word, &lut);
                new_words.push(refresh_ct);
            }
            w.push(new_words);
        }
        // Each word stored in w has a noise level of 1.
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

    /*  adds a scalar to the state, used for (iv + i) step before AES encryption. This implementation is very inefficient
    due to the need of circuit bootstrapping (CBS) for each byte addition. Ideally you would compute this (iv + i) in a PBS paramter-set and keyswitch to the WoPBS paramter-set to do AES encryption, but not sure if this is feasible with 
    the WoPBS paramters I've chosen.  */
    pub fn add_scalar(&self, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, i: u128) {
        // we convert index i to a vector of bytes from MSB to LSB.
        let mut i_blocks = vec![];
        for j in (0..16).rev() {
            let block = ((i >> (8 * j)) & 0xFF) as u64;
            i_blocks.push(block);
        }

        // f function for addition result and g function for carry computation
        let f = |x| -> u64 { (x + i as u64) % 256 };
        let g = |x| -> u64 { if x + i as u64 > 255 { 1 } else { 0 } };
        let lut_f = gen_lut(
            self.wopbs_key_short.param.message_modulus.0 as usize,
            self.wopbs_key_short.param.carry_modulus.0 as usize,
            self.wopbs_key_short.param.polynomial_size.0,
            8,
            f,
        );
        let lut_g = gen_lut(
            self.wopbs_key_short.param.message_modulus.0 as usize,
            self.wopbs_key_short.param.carry_modulus.0 as usize,
            self.wopbs_key_short.param.polynomial_size.0,
            8,
            g,
        );
        let luts = vec![lut_f, lut_g];

        // we use many wopbs to compute the two luts for the cost of 1 CBS
        let results = many_wopbs_without_padding(state.last_mut().unwrap(), &self.wopbs_key_short, luts);

        // our new_state which will hold iv + i at the end.
        let mut new_state = Vec::new();
        new_state.push(results[0].clone());

        // our carrys generated at each step
        let carry = results[1].blocks()[0].clone();
        let mut carrys = Vec::new();
        carrys.push(carry);

        let mut c = 0;
        // We iterate through the state from LSB to MSB
        for index in (0..15).rev() {

            // We create a radix ciphertext of 9 blocks, where the first 8 blocks are the state and the last block is the carry
            let blocks = state[index].blocks();
            let mut new_blocks = Vec::new();
            for block in blocks.iter() {
                new_blocks.push(block.clone());
            }
            new_blocks.push(carrys[c].clone());
            let mut new_radix = BaseRadixCiphertext::from_blocks(new_blocks);

            // same as before, but the difference is we compute two 9-9 luts, where the first 8 bits are the state and the last bit is the carry
            let fp = |x: u64| -> u64 {
                ((x & 0xFF) + ((x >> 8) & 0x1) + (i_blocks[index])) % 256
            };
            let gp = |x: u64| -> u64 {
                if ((x & 0xFF) + ((x >> 8) & 0x1) + (i_blocks[index])) > 255 {
                    1
                } else {
                    0
                }
            };
            let lut_fp = gen_lut(
                self.wopbs_key_short.param.message_modulus.0 as usize,
                self.wopbs_key_short.param.carry_modulus.0 as usize,
                self.wopbs_key_short.param.polynomial_size.0,
                9,
                fp,
            );
            let lut_gp = gen_lut(
                self.wopbs_key_short.param.message_modulus.0 as usize,
                self.wopbs_key_short.param.carry_modulus.0 as usize,
                self.wopbs_key_short.param.polynomial_size.0,
                9,
                gp,
            );
        
            // Use many_wopbs_without_padding
            let luts = vec![lut_fp, lut_gp];
            let resultsp = many_wopbs_without_padding(&mut new_radix, &self.wopbs_key_short, luts);

            // we push the result of the addition to our new_state and store the carry for the next step
            let res_blocks = resultsp[0].blocks();
            let mut new_blocks = Vec::new();
            for i in 0..res_blocks.len()-1 {
                new_blocks.push(res_blocks[i].clone());
            }
            let new_radix_block = BaseRadixCiphertext::from_blocks(new_blocks);

            new_state.push(new_radix_block);
            carrys.push(resultsp[1].blocks()[0].clone());
            c += 1;

        }

        // reverse vector new_state to store from MSB to LSB
        new_state.reverse();

        
    
        *state = new_state;
    }
}

// Simple addition of round key to state, which is an XOR since there is no carry and bit of padding.
fn add_round_key(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, round_key: &Vec<BaseRadixCiphertext<Ciphertext>>) {
    for (state_byte, round_key_byte) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_byte, round_key_byte);
    }
}
