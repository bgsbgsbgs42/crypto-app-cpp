# C++ Cryptography Application

A complete cryptographic toolkit that provides robust encryption, decryption, digital signatures, and hashing capabilities using industry-standard libraries.

## Features

This application provides a comprehensive suite of cryptographic operations including:
- RSA digital signatures (sign/verify)
- AES-256 encryption/decryption
- SHA-256 hashing
- File encryption with signature verification
- Base64 and hex encoding/decoding

## Prerequisites

You'll need to install the following libraries:

### On Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install libssl-dev libcrypto++-dev
```

### On macOS
```bash
brew install openssl cryptopp
```

### On Windows
- Install OpenSSL and Crypto++ with vcpkg or pre-built binaries
- Set up environment variables to point to the libraries

## Building the Application

1. Clone the repository or download the source code
2. Use the provided Makefile:

```bash
make
```

This will compile the application into an executable named `crypto_app`.

## Usage

Run the application:

```bash
./crypto_app
```

The application provides a menu-driven interface with the following options:

1. **Generate RSA Key Pair** - Creates a new RSA key pair (2048-bit by default)
2. **Sign a Message** - Signs a message using an RSA private key
3. **Verify a Signature** - Verifies a message signature using an RSA public key
4. **Generate AES Key** - Creates a new 256-bit AES key
5. **Encrypt a Message** - Encrypts a message using AES-256 in CBC mode
6. **Decrypt a Message** - Decrypts a message using AES-256 in CBC mode
7. **Compute SHA-256 Hash** - Calculates a SHA-256 hash of a message
8. **Encrypt and Sign a File** - Encrypts a file with AES and signs it with RSA
9. **Verify and Decrypt a File** - Verifies a signature and decrypts a file
0. **Exit** - Quits the application

## Security Notes

- This application is meant for educational purposes
- For production use, consider:
  - More robust error handling
  - Secure key management practices (HSMs, key rotation)
  - Memory protection for sensitive data (secure memory allocation)
  - Protection against side-channel attacks
  - Proper random number generation with entropy assessment
  - Secure file deletion methods
  - Regular security audits
  - Compliance with relevant cryptographic standards (FIPS, etc.)

## File Format

When encrypting and signing files, the application uses the following format:
- First 16 bytes: Initialization Vector (IV)
- Next 4 bytes: Signature length (big-endian 32-bit unsigned integer)
- Next N bytes: Signature (where N is the signature length)
- Remaining bytes: Encrypted data

## Implementation Details

- RSA signatures are created using SHA-256 hashing and RSA signing
- AES encryption uses 256-bit keys in CBC mode with a random IV
- Base64 and hex encoding are used for displaying binary data
- Key generation uses cryptographically secure random number generators
- Error handling uses OpenSSL's error reporting capabilities
- Memory management follows RAII principles where possible

## Example Usage

Here's a typical workflow for encrypting and signing a file:

```
1. Generate RSA Key Pair (option 1)
   - Enter private key filename: private.pem
   - Enter public key filename: public.pem

2. Generate AES Key (option 4)
   - Save key to file for future use if needed

3. Encrypt and Sign File (option 8)
   - Enter input file: secret_document.txt
   - Enter output file: secret_document.enc
   - Enter private key file: private.pem

4. To decrypt later (option 9):
   - Enter input file: secret_document.enc
   - Enter output file: secret_document_decrypted.txt
   - Enter public key file: public.pem
```

## Troubleshooting

- **OpenSSL Error**: Ensure OpenSSL libraries are properly installed and linked
- **File Access Errors**: Verify file paths and permissions
- **Verification Failures**: Ensure you're using the correct key pair
- **Decryption Errors**: Check that the same AES key and IV are used for decryption

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is available under the MIT License.
