#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>

// OpenSSL headers
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Crypto++ headers
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>

// Function to handle OpenSSL errors
void handleOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Utility function to convert binary data to hex string
std::string binToHex(const std::vector<unsigned char>& data) {
    std::string result;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
    encoder.Put(data.data(), data.size());
    encoder.MessageEnd();
    return result;
}

// Utility function to convert hex string to binary data
std::vector<unsigned char> hexToBin(const std::string& hexStr) {
    std::vector<unsigned char> result;
    CryptoPP::HexDecoder decoder(new CryptoPP::VectorSink(result));
    decoder.Put((const CryptoPP::byte*)hexStr.data(), hexStr.size());
    decoder.MessageEnd();
    return result;
}

// Base64 encode data
std::string base64Encode(const std::vector<unsigned char>& data) {
    std::string result;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(result), false);
    encoder.Put(data.data(), data.size());
    encoder.MessageEnd();
    return result;
}

// Base64 decode data
std::vector<unsigned char> base64Decode(const std::string& base64Str) {
    std::vector<unsigned char> result;
    CryptoPP::Base64Decoder decoder(new CryptoPP::VectorSink(result));
    decoder.Put((const CryptoPP::byte*)base64Str.data(), base64Str.size());
    decoder.MessageEnd();
    return result;
}

// Generate RSA key pair
void generateRSAKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile, int keySize = 2048) {
    std::cout << "Generating RSA key pair (" << keySize << " bits)..." << std::endl;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Create RSA context
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4); // RSA_F4 = 65537
    
    // Generate key pair
    if (RSA_generate_key_ex(rsa, keySize, e, nullptr) != 1) {
        BN_free(e);
        RSA_free(rsa);
        handleOpenSSLErrors();
    }
    
    // Save private key
    FILE* privKeyFile = fopen(privateKeyFile.c_str(), "wb");
    if (!privKeyFile) {
        std::cerr << "Error: Could not open file for writing private key." << std::endl;
        BN_free(e);
        RSA_free(rsa);
        return;
    }
    
    if (!PEM_write_RSAPrivateKey(privKeyFile, rsa, nullptr, nullptr, 0, nullptr, nullptr)) {
        fclose(privKeyFile);
        BN_free(e);
        RSA_free(rsa);
        handleOpenSSLErrors();
    }
    fclose(privKeyFile);
    
    // Save public key
    FILE* pubKeyFile = fopen(publicKeyFile.c_str(), "wb");
    if (!pubKeyFile) {
        std::cerr << "Error: Could not open file for writing public key." << std::endl;
        BN_free(e);
        RSA_free(rsa);
        return;
    }
    
    if (!PEM_write_RSA_PUBKEY(pubKeyFile, rsa)) {
        fclose(pubKeyFile);
        BN_free(e);
        RSA_free(rsa);
        handleOpenSSLErrors();
    }
    fclose(pubKeyFile);
    
    // Clean up
    BN_free(e);
    RSA_free(rsa);
    
    std::cout << "RSA key pair generated successfully!" << std::endl;
    std::cout << "Private key saved to: " << privateKeyFile << std::endl;
    std::cout << "Public key saved to: " << publicKeyFile << std::endl;
}

// Sign a message using RSA private key
std::vector<unsigned char> signMessage(const std::string& message, const std::string& privateKeyFile) {
    // Load private key
    FILE* privKeyFile = fopen(privateKeyFile.c_str(), "rb");
    if (!privKeyFile) {
        std::cerr << "Error: Could not open private key file." << std::endl;
        return std::vector<unsigned char>();
    }
    
    RSA* rsa = PEM_read_RSAPrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);
    
    if (!rsa) {
        handleOpenSSLErrors();
    }
    
    // Calculate SHA-256 hash of the message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.size());
    SHA256_Final(hash, &sha256);
    
    // Sign the hash
    std::vector<unsigned char> signature(RSA_size(rsa));
    unsigned int signatureLength;
    
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &signatureLength, rsa) != 1) {
        RSA_free(rsa);
        handleOpenSSLErrors();
    }
    
    // Resize the signature vector to the actual length
    signature.resize(signatureLength);
    
    // Clean up
    RSA_free(rsa);
    
    return signature;
}

// Verify a signature using RSA public key
bool verifySignature(const std::string& message, const std::vector<unsigned char>& signature, const std::string& publicKeyFile) {
    // Load public key
    FILE* pubKeyFile = fopen(publicKeyFile.c_str(), "rb");
    if (!pubKeyFile) {
        std::cerr << "Error: Could not open public key file." << std::endl;
        return false;
    }
    
    RSA* rsa = PEM_read_RSA_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
    fclose(pubKeyFile);
    
    if (!rsa) {
        handleOpenSSLErrors();
    }
    
    // Calculate SHA-256 hash of the message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.size());
    SHA256_Final(hash, &sha256);
    
    // Verify the signature
    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), signature.size(), rsa);
    
    // Clean up
    RSA_free(rsa);
    
    return result == 1;
}

// Generate a random AES key
std::vector<unsigned char> generateAESKey(int keySize = 32) { // 256 bits = 32 bytes
    std::vector<unsigned char> key(keySize);
    if (RAND_bytes(key.data(), keySize) != 1) {
        handleOpenSSLErrors();
    }
    return key;
}

// Generate a random IV
std::vector<unsigned char> generateIV() {
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
        handleOpenSSLErrors();
    }
    return iv;
}

// AES encrypt using Crypto++
std::vector<unsigned char> encryptAES(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::string ciphertext;
    
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
        
        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::StreamTransformationFilter(encryption,
                new CryptoPP::StringSink(ciphertext)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ Exception: " << e.what() << std::endl;
        return std::vector<unsigned char>();
    }
    
    return std::vector<unsigned char>(ciphertext.begin(), ciphertext.end());
}

// AES decrypt using Crypto++
std::string decryptAES(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::string decrypted;
    
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
        
        CryptoPP::StringSource(ciphertext.data(), ciphertext.size(), true,
            new CryptoPP::StreamTransformationFilter(decryption,
                new CryptoPP::StringSink(decrypted)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ Exception: " << e.what() << std::endl;
        return "";
    }
    
    return decrypted;
}

// Compute SHA-256 hash
std::vector<unsigned char> hashSHA256(const std::string& message) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.size());
    SHA256_Final(hash.data(), &sha256);
    
    return hash;
}

// Save data to file
bool saveToFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file for writing: " << filename << std::endl;
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    
    return true;
}

// Load data from file
std::vector<unsigned char> loadFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error: Could not open file for reading: " << filename << std::endl;
        return std::vector<unsigned char>();
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        std::cerr << "Error: Could not read from file: " << filename << std::endl;
        return std::vector<unsigned char>();
    }
    
    return data;
}

// Encrypt and sign a file
bool encryptAndSignFile(const std::string& inputFile, const std::string& outputFile, 
                       const std::vector<unsigned char>& aesKey, const std::string& privateKeyFile) {
    // Load the input file
    std::vector<unsigned char> fileData = loadFromFile(inputFile);
    if (fileData.empty()) {
        return false;
    }
    
    // Generate a random IV
    std::vector<unsigned char> iv = generateIV();
    
    // Encrypt the file data
    std::vector<unsigned char> encryptedData = encryptAES(std::string(fileData.begin(), fileData.end()), aesKey, iv);
    if (encryptedData.empty()) {
        return false;
    }
    
    // Sign the encrypted data
    std::vector<unsigned char> signature = signMessage(std::string(encryptedData.begin(), encryptedData.end()), privateKeyFile);
    if (signature.empty()) {
        return false;
    }
    
    // Prepare the output data: IV + Signature Length + Signature + Encrypted Data
    std::vector<unsigned char> outputData;
    
    // Add IV
    outputData.insert(outputData.end(), iv.begin(), iv.end());
    
    // Add signature length (4 bytes)
    uint32_t sigLen = signature.size();
    outputData.push_back((sigLen >> 24) & 0xFF);
    outputData.push_back((sigLen >> 16) & 0xFF);
    outputData.push_back((sigLen >> 8) & 0xFF);
    outputData.push_back(sigLen & 0xFF);
    
    // Add signature
    outputData.insert(outputData.end(), signature.begin(), signature.end());
    
    // Add encrypted data
    outputData.insert(outputData.end(), encryptedData.begin(), encryptedData.end());
    
    // Save the output data to file
    return saveToFile(outputFile, outputData);
}

// Verify and decrypt a file
bool verifyAndDecryptFile(const std::string& inputFile, const std::string& outputFile, 
                         const std::vector<unsigned char>& aesKey, const std::string& publicKeyFile) {
    // Load the input file
    std::vector<unsigned char> fileData = loadFromFile(inputFile);
    if (fileData.empty() || fileData.size() <= AES_BLOCK_SIZE + 4) {
        std::cerr << "Error: Input file is too small or empty." << std::endl;
        return false;
    }
    
    // Extract IV (first 16 bytes)
    std::vector<unsigned char> iv(fileData.begin(), fileData.begin() + AES_BLOCK_SIZE);
    
    // Extract signature length (next 4 bytes)
    uint32_t sigLen = (static_cast<uint32_t>(fileData[AES_BLOCK_SIZE]) << 24) |
                      (static_cast<uint32_t>(fileData[AES_BLOCK_SIZE + 1]) << 16) |
                      (static_cast<uint32_t>(fileData[AES_BLOCK_SIZE + 2]) << 8) |
                      static_cast<uint32_t>(fileData[AES_BLOCK_SIZE + 3]);
    
    // Ensure we have enough data
    if (fileData.size() <= AES_BLOCK_SIZE + 4 + sigLen) {
        std::cerr << "Error: Input file is corrupted or too small." << std::endl;
        return false;
    }
    
    // Extract signature
    std::vector<unsigned char> signature(fileData.begin() + AES_BLOCK_SIZE + 4, 
                                         fileData.begin() + AES_BLOCK_SIZE + 4 + sigLen);
    
    // Extract encrypted data
    std::vector<unsigned char> encryptedData(fileData.begin() + AES_BLOCK_SIZE + 4 + sigLen, fileData.end());
    
    // Verify the signature
    bool verified = verifySignature(std::string(encryptedData.begin(), encryptedData.end()), 
                                    signature, publicKeyFile);
    
    if (!verified) {
        std::cerr << "Error: Signature verification failed." << std::endl;
        return false;
    }
    
    // Decrypt the data
    std::string decryptedData = decryptAES(encryptedData, aesKey, iv);
    if (decryptedData.empty()) {
        return false;
    }
    
    // Save the decrypted data to file
    return saveToFile(outputFile, std::vector<unsigned char>(decryptedData.begin(), decryptedData.end()));
}

// Display menu
void displayMenu() {
    std::cout << "\n===== Cryptography Application Menu =====\n";
    std::cout << "1. Generate RSA Key Pair\n";
    std::cout << "2. Sign a Message\n";
    std::cout << "3. Verify a Signature\n";
    std::cout << "4. Generate AES Key\n";
    std::cout << "5. Encrypt a Message\n";
    std::cout << "6. Decrypt a Message\n";
    std::cout << "7. Compute SHA-256 Hash\n";
    std::cout << "8. Encrypt and Sign a File\n";
    std::cout << "9. Verify and Decrypt a File\n";
    std::cout << "0. Exit\n";
    std::cout << "Enter your choice: ";
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    RAND_poll();
    
    int choice;
    std::string privateKeyFile, publicKeyFile, message, inputFile, outputFile;
    std::vector<unsigned char> signature, aesKey, iv, encryptedData;
    std::string decryptedData;
    
    // Keep track of the current AES key
    std::vector<unsigned char> currentAESKey;
    
    do {
        displayMenu();
        std::cin >> choice;
        std::cin.ignore(); // Clear the newline from the input buffer
        
        switch (choice) {
            case 1: // Generate RSA Key Pair
                std::cout << "Enter private key filename: ";
                std::getline(std::cin, privateKeyFile);
                std::cout << "Enter public key filename: ";
                std::getline(std::cin, publicKeyFile);
                
                generateRSAKeyPair(privateKeyFile, publicKeyFile);
                break;
                
            case 2: // Sign a Message
                std::cout << "Enter message to sign: ";
                std::getline(std::cin, message);
                std::cout << "Enter private key filename: ";
                std::getline(std::cin, privateKeyFile);
                
                signature = signMessage(message, privateKeyFile);
                if (!signature.empty()) {
                    std::cout << "Signature created successfully." << std::endl;
                    std::cout << "Base64 encoded signature: " << base64Encode(signature) << std::endl;
                }
                break;
                
            case 3: // Verify a Signature
                std::cout << "Enter the original message: ";
                std::getline(std::cin, message);
                std::cout << "Enter Base64 encoded signature: ";
                std::string base64Sig;
                std::getline(std::cin, base64Sig);
                signature = base64Decode(base64Sig);
                
                std::cout << "Enter public key filename: ";
                std::getline(std::cin, publicKeyFile);
                
                if (verifySignature(message, signature, publicKeyFile)) {
                    std::cout << "Signature verification SUCCESSFUL." << std::endl;
                } else {
                    std::cout << "Signature verification FAILED." << std::endl;
                }
                break;
                
            case 4: // Generate AES Key
                currentAESKey = generateAESKey();
                std::cout << "AES key generated successfully." << std::endl;
                std::cout << "Hex encoded key: " << binToHex(currentAESKey) << std::endl;
                
                std::cout << "Save key to file? (y/n): ";
                char saveChoice;
                std::cin >> saveChoice;
                std::cin.ignore();
                
                if (saveChoice == 'y' || saveChoice == 'Y') {
                    std::cout << "Enter filename to save key: ";
                    std::string keyFile;
                    std::getline(std::cin, keyFile);
                    
                    if (saveToFile(keyFile, currentAESKey)) {
                        std::cout << "Key saved to file: " << keyFile << std::endl;
                    }
                }
                break;
                
            case 5: // Encrypt a Message
                if (currentAESKey.empty()) {
                    std::cout << "No AES key available. Generate one first." << std::endl;
                    break;
                }
                
                std::cout << "Enter message to encrypt: ";
                std::getline(std::cin, message);
                
                iv = generateIV();
                encryptedData = encryptAES(message, currentAESKey, iv);
                
                if (!encryptedData.empty()) {
                    std::cout << "Message encrypted successfully." << std::endl;
                    std::cout << "IV (Hex): " << binToHex(iv) << std::endl;
                    std::cout << "Encrypted (Base64): " << base64Encode(encryptedData) << std::endl;
                }
                break;
                
            case 6: // Decrypt a Message
                if (currentAESKey.empty()) {
                    std::cout << "No AES key available. Generate one first or enter a hex-encoded key: ";
                    std::string hexKey;
                    std::getline(std::cin, hexKey);
                    currentAESKey = hexToBin(hexKey);
                }
                
                std::cout << "Enter IV (Hex): ";
                std::string hexIV;
                std::getline(std::cin, hexIV);
                iv = hexToBin(hexIV);
                
                std::cout << "Enter encrypted message (Base64): ";
                std::string base64EncData;
                std::getline(std::cin, base64EncData);
                encryptedData = base64Decode(base64EncData);
                
                decryptedData = decryptAES(encryptedData, currentAESKey, iv);
                if (!decryptedData.empty()) {
                    std::cout << "Decrypted message: " << decryptedData << std::endl;
                }
                break;
                
            case 7: // Compute SHA-256 Hash
                std::cout << "Enter message to hash: ";
                std::getline(std::cin, message);
                
                std::vector<unsigned char> hash = hashSHA256(message);
                std::cout << "SHA-256 Hash (Hex): " << binToHex(hash) << std::endl;
                break;
                
            case 8: // Encrypt and Sign a File
                if (currentAESKey.empty()) {
                    std::cout << "No AES key available. Generate one first." << std::endl;
                    break;
                }
                
                std::cout << "Enter input file: ";
                std::getline(std::cin, inputFile);
                std::cout << "Enter output file: ";
                std::getline(std::cin, outputFile);
                std::cout << "Enter private key file: ";
                std::getline(std::cin, privateKeyFile);
                
                if (encryptAndSignFile(inputFile, outputFile, currentAESKey, privateKeyFile)) {
                    std::cout << "File encrypted and signed successfully." << std::endl;
                    std::cout << "Output saved to: " << outputFile << std::endl;
                }
                break;
                
            case 9: // Verify and Decrypt a File
                if (currentAESKey.empty()) {
                    std::cout << "No AES key available. Enter a hex-encoded key: ";
                    std::string hexKey;
                    std::getline(std::cin, hexKey);
                    currentAESKey = hexToBin(hexKey);
                }
                
                std::cout << "Enter input file: ";
                std::getline(std::cin, inputFile);
                std::cout << "Enter output file: ";
                std::getline(std::cin, outputFile);
                std::cout << "Enter public key file: ";
                std::getline(std::cin, publicKeyFile);
                
                if (verifyAndDecryptFile(inputFile, outputFile, currentAESKey, publicKeyFile)) {
                    std::cout << "File verification and decryption successful." << std::endl;
                    std::cout << "Output saved to: " << outputFile << std::endl;
                }
                break;
                
            case 0: // Exit
                std::cout << "Exiting the program. Goodbye!" << std::endl;
                break;
                
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
        
    } while (choice != 0);
    
    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
