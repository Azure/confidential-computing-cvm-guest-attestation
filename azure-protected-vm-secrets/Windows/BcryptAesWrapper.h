// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include "../AesWrapper.h"
#include <Windows.h>
#include <bcrypt.h>

class GcmChainingInfo : public AesChainingInfo
{
public:
    GcmChainingInfo(BCRYPT_ALG_HANDLE algHandle);
    ~GcmChainingInfo();

    void SetNonce(const std::vector<unsigned char> &nonce) noexcept; 
    void SetInitVector(const std::vector<unsigned char> &initVector) noexcept;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* GetAuthInfo() noexcept;
    std::vector<unsigned char> GetNonce() noexcept;
    std::vector<unsigned char> GetInitVector() noexcept;
private:
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> initVector;
    std::vector<unsigned char> authTag;
    std::vector<unsigned char> macContext;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
};

// Wrapper class for AES encryption and decryption
class GcmWrapper : public AesWrapper
{
public:
    GcmWrapper();

    ~GcmWrapper();

    // Set the key to be used for encryption and decryption
    // key: The key to be used for encryption and decryption
    // return: void
    void SetKey(std::vector<unsigned char> &key);

    // Initialize the authInfo structure and set the nonce to be used
    // for encryption and decryption
    // nonce: The nonce to be used for encryption and decryption
    // return: void
    std::unique_ptr<AesChainingInfo> SetChainingInfo(const std::vector<unsigned char> &nonce);

    // Encrypt the data using the key and chaining mode set
    // data: The data to be encrypted
    // return: The encrypted data
    std::vector<unsigned char> Encrypt(const std::vector<unsigned char> &data, AesChainingInfo *chainingInfo) const;

    // Decrypt the data using the key and chaining mode set
    // ciphertext: The data to be decrypted
    // return: The decrypted data
    std::vector<unsigned char> Decrypt(const std::vector<unsigned char> &ciphertext, AesChainingInfo *chainingInfo) const ;

private:
    std::vector<unsigned char> authTag;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> initVector;
    
#ifndef PLATFORM_UNIX
    // Windows specific members for Bcrypt
    std::vector<unsigned char> objectValue;
    std::vector<unsigned char> macContext;
    BCRYPT_ALG_HANDLE hAesHandle;
    BCRYPT_KEY_HANDLE hAesKey;
    DWORD blockLength = 0;
    DWORD objectLength = 0;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
#else
#endif // !PLATFORM_UNIX

};

class GcmCreator : public AesCreator {
public:
    std::unique_ptr<AesWrapper> CreateAesWrapper() const override {
        return std::make_unique<GcmWrapper>();
    }
};