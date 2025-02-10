# **Fully Homomorphic Encryption (FHE) Implementation of AES-128 using TFHE-rs**

This repository provides a complete implementation of a fully homomorphic version of the AES-128 cryptosystem operating in CTR mode, utilizing the TFHE Fully Homomorphic Encryption (FHE) scheme for efficient evaluation.


---

# **Build and Execute**

Clone the repository and run in release mode

```bash
git clone git@github.com:rostin79s/TFHE-AES.git
cd TFHE-AES
cargo build
cargo run --release -- --number-of-outputs <NUM_OUTPUTS> --iv <IV_VALUE> --key <KEY_VALUE>
```
The command arguments are provided in integer format. The main function executes **AES CTR mode** in **FHE** for the specified number of outputs. It FHE-encrypts messages from `iv` to `iv + n-1` and verifies the correctness using the [`aes` crate](https://crates.io/crates/aes).


---

# **Usage**
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


# **Implementation Details**

This project implements AES encryption by utilizing techniques used in the literature based on the **TFHE** (Fully Homomorphic Encryption) scheme, specifically leveraging **WoPBS** primitives. It integrates circuit bootstrapping to compute the S-Box operation efficiently, and we employ an optimization to reduce execution time even further.

## Overview

The AES encryption is performed in our framework using the following operations:

1. **S-Box**: WoPBS is applied to compute the S-Box.
2. **Mix Columns**: Implemented using LWE (Learning With Errors) additions.
3. **Shift Rows**: Simple data movement by swapping ciphertexts.
4. **Add Round Key**: Implemented with a single LWE addition.

We utilize the WoPBS primitives as described in the paper [WoPBS: A Homomorphic Encryption Primitive for Efficient Polynomial Evaluation](https://eprint.iacr.org/2022/704.pdf).

---

## AES Operations with TFHE

Each encrypted bit of the message is represented as a single LWE ciphertext in the **WoPBS** parameter context, where it supports 1 bit of message_modulus, with no padding and carry. This is crucial since AES operations such as `add round key` and `mix columns` require XOR operations, which can be done using relatively free LWE additions, due to the specific LWE construction. Each byte of the message is encrypted as a radix ciphertext, where each block is a 1-bit shortint ciphertext.

### 1. **S-Box Operation**

Each encrypted byte (8 bits) is circuit-bootstrapped using WoPBS, applying the S-Box lookup table (LUT), and returning the result in the same format.

### 2. **Shift Rows**

`Shift rows` in AES is a simple operation that requires moving radix ciphertexts to the correct position.

### 3. **Mix Columns**

`Mix Columns` in AES encryption is implemented using additions based on the following equations:

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

### 4. **Add Round Key**

The `Add Round Key` operation is done using XOR between the ciphertext and the round key. Due to our parameterization, we can do XOR with almost free LWE additions.

---

## Optimization Strategy

### **Embedding mul2 and mul3 in S-Box Evaluation**

To reduce the number of leveled additions required between WoPBS calls, we can embed the **mul2** and **mul3** operations  within the **S-Box** LUT evaluation. By performing **multi-LUT WoPBS** (evaluating multiple LUTs with the cost of one 8-bit circuit bootstrapping), we significantly reduce the number of additions and therefore the log2 norm required, lowering the execution time and parameter complexity.

This approach enables the generation of multiple LUTs (one for normal S-Box, one for mul2(S-Box), and one for mul3(S-Box)) by circuit bootstrapping 8 bits.

### **Decryption**

The decryption process is similar to encryption with everything being inverse. However, a major issue is that the round key is applied after the S-Box operation and before the inverse Mix Columns. This extra round key addition prevents embedding the mul operations in the S-Box LUT evaluation. To keep the addition depth minimum, we must evaluate another LUT (compute each mul for each byte) after the round key, which almost doubles the execution time compared to AES encryption.

---

## Key Expansion

AES key expansion is performed using the same primitives as the AES encryption process, involving S-Box evaluations, XORs, and data movements. However, to reduce addition depth, we apply WoPBS to each generated byte of the round keys to refresh the noise, so each byte is at noise level 1.

---

## Parameterization

The custom parameter set for WoPBS evaluation is chosen to guarantee **128 bits of security** and a failure probability of \$2^{-64}$, using the optimizer found in [Concrete Optimizer](https://github.com/zama-ai/concrete/tree/main/compilers/concrete-optimizer).

- **Failure Probability**: $6.1 \times 10^{-20}$
- **Security**: At least 128 bits
- **Log Norm2**: 5
- **Max Noise Level (Additions)**: $\lfloor \sqrt{2^5} \rfloor = 5$ (sufficient for all AES operations)

---

## Performance

The AES encryption time achieved using this approach is **84 seconds**, which is comparable to the **Fregata implementation** (86 seconds).
