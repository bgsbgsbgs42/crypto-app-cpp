#C++ Cryptography Application
This application provides a comprehensive suite of cryptographic operations including:

RSA digital signatures (sign/verify)
AES encryption/decryption
SHA-256 hashing
File encryption with signature verification
Prerequisites
You'll need to install the following libraries:

On Debian/Ubuntu
sudo apt-get update
sudo apt-get install libssl-dev libcrypto++-dev

On macOS
brew install openssl cryptopp

On Windows
Install OpenSSL and Crypto++ with vcpkg or pre-built binaries
Set up environment variables to point to the libraries
Building the Application
Clone the repository or download the source code

Use the provided Makefile:
make
This will compile the application into an executable named crypto_app.

Usage
Run the application:

./crypto_app
The application provides a menu-driven interface with the following options:

Generate RSA Key Pair - Creates a new RSA key pair (2048-bit by default)
Sign a Message - Signs a message using an RSA private key
Verify a Signature - Verifies a message signature using an RSA public key
Generate AES Key - Creates a new 256-bit AES key
Encrypt a Message - Encrypts a message using AES-256 in CBC mode
Decrypt a Message - Decrypts a message using AES-256 in CBC mode
Compute SHA-256 Hash - Calculates a SHA-256 hash of a message
Encrypt and Sign a File - Encrypts a file with AES and signs it with RSA
Verify and Decrypt a File - Verifies a signature and decrypts a file
Exit - Quits the application
Security Notes
This application is meant for educational purposes
For production use, consider:
More robust error handling
Secure key management practices
Memory protection for sensitive data
Protection against side-channel attacks
Proper random number generation
Secure file deletion methods
File Format
When encrypting and signing files, the application uses the following format:

First 16 bytes: Initialization Vector (IV)
Next 4 bytes: Signature length (big-endian 32-bit unsigned integer)
Next N bytes: Signature (where N is the signature length)
Remaining bytes: Encrypted data

Implementation Details
RSA signatures are created using SHA-256 hashing and RSA signing
AES encryption uses 256-bit keys in CBC mode with a random IV
Base64 and hex encoding are used for displaying binary data
Key generation uses cryptographically secure random number generators

License
This project is available under the MIT License.
