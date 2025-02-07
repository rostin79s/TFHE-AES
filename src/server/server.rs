use tfhe::{
    integer::{
        backward_compatibility::public_key, ciphertext::BaseRadixCiphertext, wopbs::WopbsKey, PublicKey, ServerKey
    }, shortint::Ciphertext
};

use super::sbox::{
    sbox::sbox,
    gen_lut::gen_lut
};
use super::encrypt::mix_columns;
use super::encrypt::shift_rows;

use super::decrypt::inv_mix_columns;
use super::decrypt::inv_shift_rows;
use super::key_expansion::key_expansion_utils::{RCON, fhe_rot_word, fhe_sub_word};

use rayon::prelude::*;

pub struct Server {
    public_key: PublicKey,
    sks: ServerKey,
    wopbs_key: WopbsKey,
}

impl Server {
    pub fn new(public_key: PublicKey, sks: ServerKey, wopbs_key: WopbsKey) -> Self {
        Server { public_key, sks, wopbs_key }
    }

    pub fn aes_encrypt(&self, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>> , state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, i: u64){
        // this should be scalar without noise, however the scalar addition functions 
        // do not work for the no padding case. We apply sbox (LUT) right after this and
        // round key so this extra noise won't affect anything.
        let encrypted_i = self.public_key.encrypt_radix_without_padding(i as u64, 8);
        
        self.sks.unchecked_add_assign(state.last_mut().unwrap(), &encrypted_i);

        let rounds = 10;

        let zero = self.public_key.encrypt_radix_without_padding(0 as u64,8); //  THIS NEEDS TO BE FIXED ???????????????????????????????????????????????????????????

        add_round_key(&self.sks,  state, &encrypted_round_keys[0]);

        for round in 1..rounds {
            // for byte_ct in state.iter_mut() {
            //     sbox(wopbs_key, byte_ct, false);
            // }

            state.par_iter_mut().for_each(|byte_ct| {
                sbox(&self.wopbs_key, byte_ct, false);
            });

            shift_rows(state);
            mix_columns(&self.sks, state, &zero);
            add_round_key(&self.sks, state, &encrypted_round_keys[round]);
        }

    
        state.par_iter_mut().for_each(|byte_ct| {
            sbox(&self.wopbs_key, byte_ct, false);
        });
        shift_rows(state);
        add_round_key(&self.sks, state, &encrypted_round_keys[rounds]);
    }

    pub fn aes_decrypt(&self, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>>, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>){
        let rounds = 10;

        add_round_key(&self.sks, state, &encrypted_round_keys[rounds]);
        // debug_state(state, rounds, &self.public_key, "add round key");

        let zero = &self.public_key.encrypt_radix_without_padding(0 as u64, 8);

        for round in (2..=rounds).rev() {
            inv_shift_rows(state);
            // debug_state(state, round, &self.public_key, "inv shift rows");

            state.par_iter_mut().for_each(|byte_ct| {
                sbox(&self.wopbs_key, byte_ct, true);
            });
            // debug_state(state, round, &self.public_key, "sbox");

            add_round_key(&self.sks, state, &encrypted_round_keys[round - 1]);
            // debug_state(state, round, &self.public_key, "add round key");

            inv_mix_columns(&self.sks, state, &zero);
            // debug_state(state, round, &self.public_key, "inv mix columns");
        }

        inv_shift_rows(state);
        // debug_state(state, 1, &self.public_key, "inv shift rows");

        state.par_iter_mut().for_each(|byte_ct| {
            sbox(&self.wopbs_key, byte_ct, true);
        });
        // debug_state(state, 1, &self.public_key, "sbox");

        add_round_key(&self.sks, state, &encrypted_round_keys[0]);
        // debug_state(state, 1, &self.public_key, "add round key");
    }

    pub fn aes_key_expansion(&self, key: &Vec<BaseRadixCiphertext<Ciphertext>>) -> Vec<Vec<BaseRadixCiphertext<Ciphertext>>> {
        let nk = 4; // Number of 32-bit words in the key for AES-128
        let nb = 4; // Number of columns in the fhe_encrypted_state
        let nr = 10; // Number of rounds for AES-128
        let mut w = Vec::new(); // Word array to hold expanded keys
    
        let message_mod = 2;
        let carry_mod = 1;
        let poly_size = 512;
        let f = |x| x as u64;
    
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
                fhe_sub_word(&self.wopbs_key, &mut temp);
                let rcon_byte= RCON[(i / nk) - 1] as u64;
                let encrypted_rcon = &self.public_key.encrypt_radix_without_padding(rcon_byte as u64, 8);
                temp[0] = self.sks.unchecked_add(&temp[0], &encrypted_rcon);
            }
            let mut new_words = Vec::new();
    
            for j in 0..4 {
                let lut = gen_lut(message_mod, carry_mod, poly_size, &w[i - nk][j], f);
                // let refresh_ct = wopbs_key.wopbs_without_padding(&w[i - nk][j], &lut);
                // w[i - nk][j] = refresh_ct;
    
    
                let new_word = &self.sks.unchecked_add(&w[i - nk][j], &temp[j]);
                let refresh_ct = self.wopbs_key.wopbs_without_padding(new_word, &lut);
                new_words.push(refresh_ct);
            }
            w.push(new_words);
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
}

fn add_round_key(sks: &ServerKey, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, round_key: &Vec<BaseRadixCiphertext<Ciphertext>>) {
    for (state_byte, round_key_byte) in state.iter_mut().zip(round_key.iter()) {
        sks.unchecked_add_assign(state_byte, round_key_byte);
    }
}

