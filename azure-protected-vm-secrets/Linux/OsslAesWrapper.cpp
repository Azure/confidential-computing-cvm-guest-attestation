// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>
#include "OsslAesWrapper.h"
#include "OsslError.h"

static std::vector<unsigned char> generate_random_bytes(size_t num) {
   std::vector<unsigned char> bytes(num);
   if (RAND_bytes(bytes.data(), num) != 1) {
       throw std::runtime_error("Failed to generate random bytes");
   }
   return bytes;
}

OsslGcmChainingInfo::OsslGcmChainingInfo() {
}

OsslGcmChainingInfo::~OsslGcmChainingInfo() {
}

void OsslGcmChainingInfo::SetNonce(const std::vector<unsigned char> &nonce) noexcept {
    this->nonce = nonce;
}

std::vector<unsigned char> OsslGcmChainingInfo::GetNonce() noexcept {
    return nonce;
}

void OsslGcmChainingInfo::SetInitVector(const std::vector<unsigned char> &initVector) noexcept {
    this->initVector = initVector;
}

std::vector<unsigned char> OsslGcmChainingInfo::GetInitVector() noexcept {
    return initVector;
}

OsslGcmWrapper::OsslGcmWrapper() {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
}

OsslGcmWrapper::~OsslGcmWrapper() {
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;
    }
}

void OsslGcmWrapper::SetKey(std::vector<unsigned char> &key) {
    this->key = key;
}

std::unique_ptr<AesChainingInfo> OsslGcmWrapper::SetChainingInfo(const std::vector<unsigned char> &nonce) {
    std::unique_ptr<AesChainingInfo> chainingInfo = std::make_unique<OsslGcmChainingInfo>();
    chainingInfo->SetInitVector(nonce);
    return chainingInfo;
}

std::vector<unsigned char> OsslGcmWrapper::Encrypt(const std::vector<unsigned char> &data, AesChainingInfo* chainingInfo) const {
    if (!chainingInfo) {
        throw std::runtime_error("Chaining info must be set before calling Encrypt");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw OsslError(ERR_get_error(), "Failed to initialize encryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, chainingInfo->GetInitVector().size(), nullptr) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set IV length");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), chainingInfo->GetInitVector().data()) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set key and IV");
    }

    std::vector<unsigned char> ciphertext(data.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size()) != 1) {
        throw OsslError(ERR_get_error(), "Failed to encrypt");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        throw OsslError(ERR_get_error(), "Failed to finalize encryption");
    }
    ciphertext_len += len;

    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1) {
        throw OsslError(ERR_get_error(), "Failed to get tag");
    }

    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

std::vector<unsigned char> OsslGcmWrapper::Decrypt(const std::vector<unsigned char> &ciphertext, AesChainingInfo* chainingInfo) const {
    if (!chainingInfo) {
        throw std::runtime_error("Chaining info must be set before calling Decrypt");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw OsslError(ERR_get_error(), "Failed to initialize decryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, chainingInfo->GetInitVector().size(), nullptr) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set IV length");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), chainingInfo->GetInitVector().data()) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set key and IV");
    }

    std::vector<unsigned char> plaintext(ciphertext.size() - 16);
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size() - 16) != 1) {
        throw OsslError(ERR_get_error(), "Failed to decrypt");
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(ciphertext.data() + ciphertext.size() - 16)) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set tag");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        throw OsslError(ERR_get_error(), "Failed to finalize decryption (tag mismatch?)");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    return plaintext;
}