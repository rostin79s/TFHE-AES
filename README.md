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
The command arguments are given in integer format. The main function executes
AES CTR mode in FHE for the number of outputs given, FHE encrypting messages iv ... iv + n-1, and verifies the correctness using the 'aes' crate [here](https://crates.io/crates/aes)
.

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
The client.rs has a Client struct, which generates the parameters and FHE keys when a client object is created and initialized.
It also has an encrypt function where you FHE encrypt the message (in the case of AES CTR we name it iv), and the AES key, sends these and
the FHE keys needed for the hypothetical server.

server.rs has a Server struct, which initializes by setting the FHE keys received from the client. It has 3 main functions to use, 'aes_key_expansion', 'aes_encryption'
and 'aes_decryption'. First, the key expansion must be called on the FHE encrypted AES key, and return 11 FHE encrypted round keys. You then call the encryption function by passing the round keys and the FHE encrypted message (iv) received from the client. Similarly, you can homomorphically decrypt an AES ciphertext by calling the decryption function. Each folder in the server directory has primitives needed for each function and operation.

---
## **Implementation techniques**

