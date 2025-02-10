# **Fully Homomorphic Encryption (FHE) Implementation of AES-128 using TFHE-rs**

This repository contains a full Implementation of a fully homomorphic version of the AES-128 cryptosystem in CTR mode, using TFHE.


---

## **Build and Execute**

Clone the repository and run in release mode

```bash
git clone git@github.com:rostin79s/TFHE-AES.git
cd TFHE-AES
cargo build
cargo run --release -- --number-of-outputs <NUM_OUTPUTS> --iv <IV_VALUE> --key <KEY_VALUE>
```
The command arguments are provided in integer format. The main function executes **AES CTR mode** in **FHE** for the specified number of outputs. It FHE-encrypts messages from `iv` to `iv + n-1` and verifies the correctness using the [`aes` crate](https://crates.io/crates/aes).


---

## **Usage**
Here is the General layout of our directory
```plaintext
project_root/
│-- src/
│   ├── main.rs
│   ├── client/
│   │   ├── client.rs
│   │   └── mod.rs
│   ├── tables/
│   │   ├── table.rs
│   │   └── mod.rs
│   ├── server/
│   │   ├── server.rs
│   │   ├── decrypt/
│   │   ├── encrypt/
│   │   ├── key_expansion/
│   │   ├── sbox/
│   │   └── mod.rs
```

### **Client**

The `client.rs` file defines a `Client` struct that performs the following functions:

- **Client Initialization:** When a `Client` object is created, it generates the parameters and the necessary FHE keys.
- **Encrypt:** The `encrypt` function is responsible for FHE-encrypting the message (referred to as `iv` in the case of AES CTR) and the AES key. It then sends the encrypted values, along with the FHE keys, to the server.



### **Server**

The `server.rs` file defines a `Server` struct which initializes with the FHE keys received from the client. It exposes three main functions:

- **aes_key_expansion:** This function expands the FHE-encrypted AES key and returns 11 FHE-encrypted round keys.
- **aes_encryption:** Using the round keys and the FHE-encrypted message (`iv`), this function performs AES encryption.
- **aes_decryption:** This function performs homomorphic decryption of the AES ciphertext.



### **Helper Functions**

The `server` directory contains several folders, each containing primitives necessary for performing specific functions and operations related to AES encryption/decryption. These include:

- **Decrypt and Encrypt Folders:** Implement the (inverse) mix columns and (inverse) shift rows functions required for AES encryption and decryption.
- **Key Expansion Folder:** Contains helper functions for the key expansion algorithm, such as bitwise rotations and S-box evaluation on words.
- **Sbox Folder:** Implements the S-box function using look-up tables and contains the helper functions such as lut generation and multi-lut evaluation which are required for the S-box operations.


## **Implementation Details**
The SOTA AES encryption based on TFHE is [Fregata](https://link.springer.com/chapter/10.1007/978-3-031-49187-0_20), where they use circuit bootstrapping to compute Sbox, and the rest of the encryption operations (mix columns, shift rows, add round key) can be implemented using LWE additions and data movement. We utilize the same techniques using the WoPBS primitives described [here](https://eprint.iacr.org/2022/704.pdf).

Each encrypted bit of the message is represented as a single LWE ciphertext in the WoPBS parameter context, where it supports 1 bit of message_modulus, with no padding and carry. This is crucial since AES operations such as `add round key` and `mix columns` require XOR operations, which can be done using relatively free LWE additions, due to the specific LWE construction. Each byte of the message is encrypted as a radix ciphertext, where each block is a 1-bit shortint ciphertext.

Sbox operation, The WoPBS operation extracts the message bit and circuit bootstraps every 8 bits, applies the SBOX lut, and returns the result in the same format.

`Shift rows` is simple data movement, by swapping the radix ciphertexts to the right spot.

`Mix columns` can be implemented with additions, using the equations below:

$$
\text{MixColumns}(S) = 
\begin{bmatrix}
02 & 03 & 01 & 01 \\
01 & 02 & 03 & 01 \\
01 & 01 & 02 & 03 \\
03 & 01 & 01 & 02
\end{bmatrix}
\begin{bmatrix}
S_0 \\
S_1 \\
S_2 \\
S_3
\end{bmatrix}
$$

$$
S'_0 = 02 \cdot S_0 \oplus 03 \cdot S_1 \oplus 01 \cdot S_2 \oplus 01 \cdot S_3
$$

$$
S'_1 = 01 \cdot S_0 \oplus 02 \cdot S_1 \oplus 03 \cdot S_2 \oplus 01 \cdot S_3
$$

$$
S'_2 = 01 \cdot S_0 \oplus 01 \cdot S_1 \oplus 02 \cdot S_2 \oplus 03 \cdot S_3
$$

$$
S'_3 = 03 \cdot S_0 \oplus 01 \cdot S_1 \oplus 01 \cdot S_2 \oplus 02 \cdot S_3
$$

and multiplication by 2 (mul2) in GF(256) can be implemented using this equation:

$$
b_0b_1b_2b_3b_4b_5b_6b_7 \xrightarrow{\times 2} b_7b_0b_1b_2b_3b_4b_5b_6 \oplus 0x0b_70b_7b_7000
$$

Where:
- $b_0b_1b_2b_3b_4b_5b_6b_7$ is the byte value before the multiplication.
- $[s_0, s_1, s_2, s_3]$ is a column in the AES state.

While the entirety of the mix columns operation (and also its inverse) can be implemented with XORS, the number of leveled additions needed for mix columns and `add round key` between WoPBS calls will be large. To Decrease this, we can embed the mul2 and mul3 functions in the SBOX evaluation, by computing multi-lut WoPBS without padding. Since circuit bootstrapping dominates the execution time of WoPBS evaluation, the actual LUT evaluation (called vertical packing) is very cheap. We can generate multiple luts (one normal Sbox, one mul2(sbox), and mul3(sbox)), and only circuit bootstrap the byte once, and evaluate the luts. in the AES encryption case, it would be an 8-24 lut, where 24 bits will be outputted. This reduces the additions required between WoPBS calls, which reduces the log2 norm required, which results in cheaper parameter sets.



decryption is the same as encryption but inverse but with one major difference. Unlike encryption, in decryption there is an add round key between the Sbox operation and the inverse mix column operation, therefore we cannot embed the mul operations in the Sbox LUT evaluation. To keep the addition depth minimum, we must evaluate another LUT (compute each mul for each byte) after the round key, which almost doubles the execution time compared to AES encryption.

AES key expansion can be easily implemented using the primitives discussed above, as it also uses the SBOX, XORs, and data movement. However, to reduce addition depth, we apply WoPBS to each generated byte of the round keys to refresh the noise, so each byte is at noise level 1.

### Parameterization
To generate the custom parameter set for WoPBS evaluation that guarantees 128 bits of security, and a failure probability of $2^{-64}$, we use the concrete optimizer found [here](https://github.com/zama-ai/concrete/tree/main/compilers/concrete-optimizer). Failure of probability for the parameter set chosen is $6.1e^{-20}$, and security of at least 128 bits, and a log norm2 of 5. The Max noise level (number of additions) will be $\sqrt(2^5) = 5$, which covers all the AES operations.

We achieved an AES encryption of 84 seconds, which is the same as Fregata (86 seconds).
