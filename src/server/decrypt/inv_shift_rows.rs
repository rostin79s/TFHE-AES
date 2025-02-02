use tfhe::shortint::Ciphertext;
use tfhe::integer::ciphertext::BaseRadixCiphertext;

pub fn inv_shift_rows(state: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    assert!(state.len() == 16, "State must have exactly 16 ciphertexts (16 bytes).");

    // Row 2: Shift right by 1
    state.swap(13, 9);
    state.swap(9, 5);
    state.swap(5, 1);

    // Row 3: Shift right by 2
    state.swap(14, 6);
    state.swap(10, 2);

    // Row 4: Shift right by 3
    state.swap(3, 7);
    state.swap(7, 11);
    state.swap(11, 15);
}