//-------------------------------------------------------------------------------------------------
// <copyright file="NativeConverter.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include "AttestationLibConst.h"
#include "NativeConverter.h"
#include "Logging.h"

using namespace attest;

bool attest::toNative(const std::string& mode_str,
                      BlockCipherMode& mode) {
    if(mode_str == std::string(JSON_RESPONSE_BLOCK_MODE_CHAINING_GCM_VALUE)) {
        mode = BlockCipherMode::CHAINING_MODE_GCM;
        return true;
    } else {
        CLIENT_LOG_ERROR("Invalid Block mode");
        mode = BlockCipherMode::Invalid;
        return false;
    }
    return false;
}

bool attest::toNative(const std::string& padding_str,
                      BlockCipherPadding& padding) {
    if(padding_str == std::string(JSON_RESPONSE_BLOCK_PADDING_PKCS7_VALUE)) {
        padding = BlockCipherPadding::PKCS7;
        return true;
    } else {
        CLIENT_LOG_ERROR("Invalid Block padding");
        padding = BlockCipherPadding::Invalid;
        return false;
    }
    return false;
}

bool attest::toNative(const std::string& cipher_str,
                      CipherAlgorithm& cipher) {
    if(cipher_str == std::string(JSON_RESPONSE_CIPHER_AES_VALUE)) {
        cipher = CipherAlgorithm::AES;
        return true;
    } else {
        CLIENT_LOG_ERROR("Invalid Cipher Algorithm");
        cipher = CipherAlgorithm::Invalid;
        return false;
    }
    return false;
}