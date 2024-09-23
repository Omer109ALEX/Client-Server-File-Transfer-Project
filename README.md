# Client-Server File Transfer Project

This project was developed as part of a final assignment for a **Software Security course**, earning a grade of 96. It implements a secure client-server communication system using symmetric and asymmetric encryption for secure file transmission.

## Overview

- **Server**: Written in Python
- **Client**: Written in C++
- **Encryption**: Combines symmetric (AES) and asymmetric (RSA) encryption methods

## Key Features

- **Symmetric encryption (AES)**: Efficient file transfer encryption
- **Asymmetric encryption (RSA)**: Secure key exchange
- **Client-server architecture**: Allows clients to securely transfer encrypted files to the server
- **Integrity verification**: Files are validated using a checksum to ensure proper transmission

## Project Details

The client initiates a connection with the server, performs a key exchange using RSA, and transmits files encrypted with AES. Upon receiving the file, the server decrypts it and verifies its integrity by comparing checksums. If the transfer is successful, the server stores the file locally.

### Server Features:
- Multi-client support using threads or selectors
- Encryption handled via Python's `Crypto.Cipher` package
- Stores client and file information in an in-memory SQLite database
- Supports file integrity verification using `cksum` command

### Client Features:
- Written in C++ using `CryptoPP` for encryption
- Runs in batch mode for automated file transfers
- Reads configuration from a text file (`transfer.info`)

## Protocol Overview

- **Key Exchange**: RSA public/private key exchange for secure key transmission
- **File Encryption**: Files are encrypted using AES before transmission
- **Integrity Check**: Both client and server compute file checksums to ensure accuracy of file transfers

For further technical details, please refer to the [Protocol Documentation](./protocol.pdf) which explains the communication protocol in depth.

---

Let me know if you'd like further tweaks or additions!
