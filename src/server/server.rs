use tfhe::{
    integer::{
        backward_compatibility::public_key, ciphertext::BaseRadixCiphertext, wopbs::WopbsKey, ClientKey, IntegerCiphertext, IntegerRadixCiphertext, PublicKey, RadixClientKey, ServerKey
    },
    shortint::Ciphertext,
};

use super::sbox::{
    sbox::{sbox,key_sbox, many_wopbs_without_padding},
    gen_lut::gen_lut
};
use super::encrypt::mix_columns;
use super::encrypt::shift_rows;

use super::decrypt::inv_mix_columns;
use super::decrypt::inv_shift_rows;
use super::key_expansion::key_expansion_utils::{RCON, fhe_rot_word, fhe_sub_word};

use rayon::prelude::*;

pub struct Server {
    cks: RadixClientKey,
    public_key: PublicKey,
    sks: ServerKey,
    wopbs_key: WopbsKey,
    wopbs_key_short: tfhe::shortint::wopbs::WopbsKey,
}

impl Server {
    pub fn new(cks: RadixClientKey, public_key: PublicKey, sks: ServerKey, wopbs_key: WopbsKey) -> Self {
        let wopbs_key_short = wopbs_key.clone().into_raw_parts();
        Server { cks, public_key, sks, wopbs_key, wopbs_key_short }
    }

    pub fn add_scalar(&self, state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, i: u128) {
  
        let i: u128 = 120;

        let mut i_blocks = vec![];
        for j in (0..16).rev() {
            let block = ((i >> (8 * j)) & 0xFF) as u64;
            i_blocks.push(block);
        }
        println!("i_blocks: {:?}", i_blocks);
        // Define the functions f and g
        let f = |x| -> u64 { (x + i as u64) % 256 };
        let g = |x| -> u64 { if x + i as u64 > 255 { 1 } else { 0 } };
    
        // Generate LUTs for f and g
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
    
        // Use many_wopbs_without_padding to generate the results
        let luts = vec![lut_f, lut_g];
        let results = many_wopbs_without_padding(state.last_mut().unwrap(), &self.wopbs_key_short, luts);

        // decrypt both byte in results
        let decrypted_results: Vec<u64> = results.iter().map(|x| self.cks.decrypt_without_padding(x)).collect();
        println!("decrypted_results: {:?}", decrypted_results);

        let mut new_state = Vec::new();
        new_state.push(results[0].clone());

        let carry = results[1].blocks()[0].clone();
        let mut carrys = Vec::new();
        carrys.push(carry);

        let mut c = 0;
        for index in (0..15).rev() {
            println!("index: {:?}", index);
            let dec_state_byte: u64 = self.cks.decrypt_without_padding(&state[index]);
            println!("dec_state_byte: {:?}", dec_state_byte);
            let blocks = state[index].blocks();
            // add blocks to carry and create new block
            let mut new_blocks = Vec::new();
            for block in blocks.iter() {
                new_blocks.push(block.clone());
            }
            new_blocks.push(carrys[c].clone());
            let mut new_radix = BaseRadixCiphertext::from_blocks(new_blocks);

            // fp should be a function where first 8 bits of x and last bit of x if all are 1, return 1, else 0
            // gp should be a function where first 8 bits as num + last bit of x as num % 256

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
        
            // Use many_wopbs_without_padding to generate the results
            let luts = vec![lut_fp, lut_gp];
            let resultsp = many_wopbs_without_padding(&mut new_radix, &self.wopbs_key_short, luts);
            println!("resultp length: {:?}", resultsp[0].blocks().len());

            // decrypt both byte in results
            let decrypted_resultsp: Vec<u64> = resultsp.iter().map(|x| self.cks.decrypt_without_padding(x)).collect();
            println!("decrypted_resultsp: {:?}", decrypted_resultsp);
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

        // reverse vector new_state
        new_state.reverse();

        let decrypted_state = state.iter().map(|x| self.cks.decrypt_without_padding(x)).collect::<Vec<u64>>();
        println!("decrypted_state: {:?}", decrypted_state);

        //decrypt vector new_state and print it
        let decrypted_new_state: Vec<u64> = new_state.iter().map(|x| self.cks.decrypt_without_padding(x)).collect();
        println!("decrypted_new_state: {:?}", decrypted_new_state);

        
    
        // Update the state with the results
        // *state = results;
    }

    pub fn aes_encrypt(&self, encrypted_round_keys: &Vec<Vec<BaseRadixCiphertext<Ciphertext>>> , state: &mut Vec<BaseRadixCiphertext<Ciphertext>>, i: u128){
        // this should be scalar without noise, however the scalar addition functions 
        // do not work for the no padding case. We apply sbox (LUT) right after this and
        // round key so this extra noise won't affect anything.
        
        self.add_scalar(state, i as u128);

        let rounds = 10;

        let zero = self.public_key.encrypt_radix_without_padding(0 as u64,8); //  THIS NEEDS TO BE FIXED ???????????????????????????????????????????????????????????

        add_round_key(&self.sks,  state, &encrypted_round_keys[0]);

        for round in 1..rounds {

            let mut mul_sbox_state: Vec<Vec<BaseRadixCiphertext<Ciphertext>>> = Vec::new();
            for byte_ct in state.iter_mut() {
                let mul_sbox_byte = sbox(&self.wopbs_key_short, byte_ct, false);
                mul_sbox_state.push(mul_sbox_byte);
            }

            let mut new_state = mix_columns(&self.sks, &mut mul_sbox_state, &zero);
            add_round_key(&self.sks, &mut new_state, &encrypted_round_keys[round]);
            *state = new_state;
        }

        for byte_ct in state.iter_mut() {
            key_sbox(&self.wopbs_key, &self.wopbs_key_short, byte_ct);
        }
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
                sbox(&self.wopbs_key_short, byte_ct, true);
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
            sbox(&self.wopbs_key_short, byte_ct, true);
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
    
        let message_mod = self.wopbs_key_short.param.message_modulus.0 as usize;
        let carry_mod = self.wopbs_key_short.param.carry_modulus.0 as usize;
        let poly_size = self.wopbs_key_short.param.polynomial_size.0;
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
                fhe_sub_word(&self.wopbs_key, &self.wopbs_key_short, &mut temp);
                let rcon_byte= RCON[(i / nk) - 1] as u64;
                let encrypted_rcon = &self.public_key.encrypt_radix_without_padding(rcon_byte as u64, 8);
                temp[0] = self.sks.unchecked_add(&temp[0], &encrypted_rcon);
            }
            let mut new_words = Vec::new();
    
            for j in 0..4 {
                let lut = gen_lut(message_mod, carry_mod, poly_size, 8, f);
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

