use tfhe::shortint::Ciphertext;
use tfhe::integer::ciphertext::BaseRadixCiphertext;

// Shifts the rows of the state matrix in AES encryption.
pub fn shift_rows(state: &mut Vec<BaseRadixCiphertext<Ciphertext>>) {
    // Row 1: No shift

    // Row 2: Shift left by 1
    state.swap(1, 5);
    state.swap(5, 9);
    state.swap(9, 13);

    // Row 3: Shift left by 2
    state.swap(2, 10);
    state.swap(6, 14);

    // Row 4: Shift left by 3
    state.swap(3, 15);
    state.swap(15, 11);
    state.swap(11, 7);
}