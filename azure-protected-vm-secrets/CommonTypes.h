// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <stdexcept>
#include <string>

// RSA padding scheme for wrapping/unwrapping the AES transport key.
enum class RsaPaddingScheme {
    Rsaes,     // PKCS1 v1.5 (TPM2_ALG_RSAES) — default
    RsaesOaep  // OAEP with SHA-256 (TPM2_ALG_OAEP)
};

inline const char* RsaPaddingSchemeToString(RsaPaddingScheme scheme) {
    switch (scheme) {
        case RsaPaddingScheme::RsaesOaep: return "rsaes-oaep";
        case RsaPaddingScheme::Rsaes:
        default: return "rsaes";
    }
}

inline RsaPaddingScheme ParseRsaPaddingScheme(const std::string& value) {
    if (value.empty() || value == "rsaes") {
        return RsaPaddingScheme::Rsaes;
    }
    if (value == "rsaes-oaep") {
        return RsaPaddingScheme::RsaesOaep;
    }
    throw std::invalid_argument("Unrecognized RSA padding scheme: " + value);
}
