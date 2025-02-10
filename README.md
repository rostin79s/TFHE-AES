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
- **Sbox Folder:** Implements the S-box function and contains the helper functions required for the S-box operations.


## **Implementation techniques**

