#pragma once

#include <memory>

#include <openssl/evp.h>

/**
 * Deleter for C-allocated pointers which are managed by STL constructs
 */
struct free_deleter {
    void operator()(void* ptr) const {
        free(ptr);
    }
};

template <typename T>
using unique_c_ptr = std::unique_ptr<T,free_deleter>;

/**
 * Deleter for OpenSSL md contexts which are managed by STL constructs
 */
struct evp_md_deleter {
    void operator()(void* ptr) const {
        EVP_MD_CTX_destroy((EVP_MD_CTX*)ptr);
    }
};

/**
 * Deleter for OpenSSL md contexts which are managed by STL constructs
 */
struct evp_cipher_deleter {
    void operator()(void* ptr) const {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ptr);
    }
};

// OpenSSL Message Digest unique ptr
using unique_evp_md = std::unique_ptr<EVP_MD_CTX, evp_md_deleter>;

// OpenSSL Cipher unique ptr
using unique_evp_cipher = std::unique_ptr<EVP_CIPHER_CTX, evp_cipher_deleter>;

