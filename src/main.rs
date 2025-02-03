mod client;
mod server;
mod tables;

use client::Client;
use server::server::{aes_encrypt, aes_decrypt};



fn main() {

    // test();

    
    let client = Client::new();

    let (cks, sks, wopbs_key, mut state, encrypted_round_keys) = client.client_encrypt();

    let start = std::time::Instant::now();

    aes_encrypt(&cks, &sks, &wopbs_key, &encrypted_round_keys, &mut state);

    let elapsed = start.elapsed();
    println!("Time taken for aes encryption: {:?}", elapsed);

    let mut fhe_decrypted_state = state.clone();

    let start = std::time::Instant::now();

    aes_decrypt(&cks, &sks, &wopbs_key, &encrypted_round_keys, &mut fhe_decrypted_state);

    let elapsed = start.elapsed();
    println!("Time taken for aes decryption: {:?}", elapsed);

    client.client_decrypt_and_verify(state, fhe_decrypted_state);

    // let mut message = 0;
    // let num_bytes = fhe_decrypted_state.len();

    // for (i, state_byte) in fhe_decrypted_state.iter().enumerate() {
    //     let decrypted_byte: u128 = cks.decrypt_without_padding(state_byte); // Decrypt as an 8-bit integer
    //     let position = (num_bytes - 1 - i) * 8; // Compute bit position from MSB
    //     message |= (decrypted_byte as u128) << position; // Store in the correct position
    // }

    // println!("Message: {:032x}", message);

}

use tfhe::{
    integer::{
        backward_compatibility::wopbs, gen_keys_radix, wopbs::*
    },
    shortint::parameters::WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
};

use tfhe::integer::*;
use tfhe::shortint::*;
// use tfhe::core_crypto::prelude::DeltaLog;
// use tfhe::core_crypto::prelude::ExtractedBitsCount;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::Degree;
use tfhe::shortint::parameters::NoiseLevel;

fn test(){
    let nb_block = 8;
    let (cks, sks) = gen_keys_radix(WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS, nb_block);

    let (cks_s, sks_s) = gen_keys(WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS);

    let ctemp = cks_s.encrypt_without_padding(1 as u64);

    let tempsize = ctemp.ct.lwe_size();
    println!("LWE size: {}", tempsize.0);


    // let wopbs_key_s = tfhe::shortint::wopbs::WopbsKey::new_wopbs_key_only_for_wopbs(&cks_s, &sks_s);



    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

    let message_mod = cks.parameters().message_modulus().0;
    let carry_mod = cks.parameters().carry_modulus().0;



    println!("Modulus: {}", message_mod);
    println!("Carry: {}", carry_mod);

    let mut moduli = 1_u64;
    for _ in 0..nb_block {
        moduli *= cks.parameters().message_modulus().0 as u64;
    }
    println!("Moduli: {}", moduli);


    let clear = 32 % moduli;
    let mut ct = cks.encrypt_without_padding(clear as u64);

    
    let wopbs_key_s = wopbs_key.clone().into_raw_parts();


    let mut blocks: &mut [tfhe::shortint::Ciphertext] = ct.blocks_mut();

    let lut: tfhe::shortint::wopbs::ShortintWopbsLUT = (0..512).map(|i| (i as u64 % 2) << 63).collect::<Vec<_>>().into();

    let start2 = std::time::Instant::now();

    let carry_modulus = wopbs_key_s.param.carry_modulus.0;
    let message_modulus = wopbs_key_s.param.message_modulus.0;

    let delta = (1u64 << 63) / (carry_modulus * message_modulus) as u64 * 2;
    let delta_log = DeltaLog(delta.ilog2() as usize);

    let nb_bit_to_extract = ExtractedBitsCount(1);

    for i in 0..8 {
        // let ct_res = wopbs_key_s.programmable_bootstrapping_without_padding(&blocks[i], &lut);
        let sag = wopbs_key_s.extract_bits(delta_log, &blocks[i], nb_bit_to_extract);

        let ciphertext_list = wopbs_key_s.circuit_bootstrapping_vertical_packing(lut.as_ref(), &sag);

        let sizecl = ciphertext_list.len();
        println!("Size: {}", sizecl);

        let ncl = ciphertext_list[0].lwe_size();
        println!("LWE size: {}", ncl.0);

        let cti = blocks[i].clone().ct;

        let ncti = cti.lwe_size();
        println!("LWE size: {}", ncti.0);
      


        let ciphertext = LweCiphertextOwned::from_container(
            sag.into_container(),
            wopbs_key_s.param.ciphertext_modulus,
        );

        let n = ciphertext.lwe_size();
        println!("LWE size: {}", n.0);

        let new_ciphertext = Ciphertext::new(
            ciphertext,
            Degree::new(message_modulus - 1),
            NoiseLevel::NOMINAL,
            MessageModulus(message_modulus),
            CarryModulus(carry_modulus),
            blocks[i].pbs_order,
        );

        blocks[i] = new_ciphertext;
    }

    let elapsed2 = start2.elapsed();
    println!("Time taken shortint bootstrapping: {:?}", elapsed2);
    



    // let res: u64 = cks_s.decrypt_message_and_carry_without_padding(&ct_res);
    // println!("Result shortint bootstrapping: {}", res);


    // let scal_s = cks_s.encrypt_without_padding(1 as u64);

    // let mut scal = cks.encrypt_without_padding(1 as u64);
    // let mut blocks_s = scal.blocks_mut();
    
    // sks_s.unchecked_add_assign(&mut blocks[0], &blocks_s[0]);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);
    // sks_s.unchecked_scalar_add_assign(&mut blocks[0], 1);

    let poly_size = 512;
    let f = |x| x as u64;
    
    let lut = gen_lut(message_mod, carry_mod, poly_size, &ct, f);

    let scal = cks.encrypt_without_padding(1 as u64);

    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);
    // sks.unchecked_add_assign(&mut ct,&scal);

    let start = std::time::Instant::now();

    let ct_res = wopbs_key.wopbs_without_padding(&ct, &lut);

    let elapsed = start.elapsed();
    println!("Time taken: {:?}", elapsed);



    let res: u64 = cks.decrypt_without_padding(&ct_res);
    println!("Result: {}", res);

}






fn gen_lut<F, T>(message_mod: usize, carry_mod: usize, poly_size: usize, ct: &T, f: F) -> IntegerWopbsLUT 
    where
        F: Fn(u64) -> u64,
        T: IntegerCiphertext,
    {
        let log_message_modulus =
            f64::log2((message_mod) as f64) as u64;
        let log_carry_modulus = f64::log2((carry_mod) as f64) as u64;
        let log_basis = log_message_modulus + log_carry_modulus;
        let delta = 64 - log_basis;
        let nb_block = ct.blocks().len();
        let poly_size = poly_size;
        let mut lut_size = 1 << (nb_block * log_basis as usize);
        if lut_size < poly_size {
            lut_size = poly_size;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(nb_block));
        for index in 0..lut_size {
            // find the value represented by the index
            let mut value = 0;
            let mut tmp_index = index;
            for i in 0..nb_block as u64 {
                let tmp = tmp_index % (1 << log_basis); // Extract only the relevant block
                tmp_index >>= log_basis; // Move to the next block
                value += tmp << (log_message_modulus * i); // Properly reconstruct `value`
            }
            // fill the LUTs
            for block_index in 0..nb_block {
                let masked_value = (f(value as u64) >> (log_message_modulus * block_index as u64))
                    % (1 << log_message_modulus);  // Mask the value using the message modulus
            
                lut[block_index][index] = masked_value << delta;  // Apply delta to the LUT entry
            }
        }
        lut
    }


