// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// #include "HKDF.h"
#include "OsslHKDF.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <vector>
#include <iostream>
#include "../DebugInfo.h"

std::vector<unsigned char> OsslSha(const std::vector<unsigned char>& data, const size_t hashSize) {
    const EVP_MD *md;
    switch (hashSize) {
        case SHA256_HASH_SIZE:
            md = EVP_sha256();
            break;
        case SHA384_HASH_SIZE:
            md = EVP_sha384();
            break;
        case SHA512_HASH_SIZE:
            md = EVP_sha512();
            break;
        default:
            throw std::invalid_argument("Unsupported hash size");
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        throw std::runtime_error("Failed to initialize hash context");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        throw std::runtime_error("Failed to update hash");
    }

    std::vector<unsigned char> hashValue(EVP_MD_size(md));
    unsigned int length = 0;

    if (EVP_DigestFinal_ex(ctx, hashValue.data(), &length) != 1) {
        throw std::runtime_error("Failed to finalize hash");
    }

    hashValue.resize(length);
    return hashValue;
}

OsslHKDF::OsslHKDF(const std::vector<unsigned char>& secret) {
    std::vector<unsigned char> hash = OsslSha(secret, SHA256_HASH_SIZE);
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        throw std::runtime_error("Failed to create HKDF context");
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to initialize HKDF context");
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set HKDF mode");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set HKDF hash function");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, hash.data(), hash.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set HKDF key");
    }
}

OsslHKDF::~OsslHKDF() {
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
}

// Derive key based on RFC 5869.
std::vector<unsigned char> OsslHKDF::DeriveKey(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, size_t keySize) {
    std::vector<unsigned char> prk = Extract(salt);
	return Expand(prk, info, keySize);
}

std::vector<unsigned char> OsslHKDF::Extract(std::vector<unsigned char> &salt) {
	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
        throw std::runtime_error("Failed to set HKDF salt");
    }
    std::vector<unsigned char> prk(SHA256_HASH_SIZE);
    return prk;
}

std::vector<unsigned char> OsslHKDF::Expand(std::vector<unsigned char> &prk, std::vector<unsigned char> &info, size_t keySize) {
    std::vector<unsigned char> okm = std::vector<unsigned char>(keySize);
	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
        throw std::runtime_error("Failed to set HKDF info");
    }
    if (EVP_PKEY_derive(pctx, okm.data(), &keySize) <= 0) {
        throw std::runtime_error("Failed to derive HKDF output key material");
    }
	return okm;
}