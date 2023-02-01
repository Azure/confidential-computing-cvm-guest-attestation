//-------------------------------------------------------------------------------------------------
// <copyright file="TpmUnseal.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <openssl/evp.h>
#include <openssl/err.h>

#include "AttestationHelper.h"
#include "AttestationLibConst.h"
#include "AttestationLibUtils.h"
#include "NativeConverter.h"
#include "TpmUnseal.h"
#include "Logging.h"

using namespace attest;


bool attest::GetEncryptionParameters(const Json::Value& json_obj,
                                     EncryptionParameters& encryption_params,
                                     std::string& err) {

    err.clear();

    Json::Value encryption_params_obj = json_obj.get(JSON_RESPONSE_EXCRYPTION_PARAMETERS_KEY,
                                                     Json::Value());
    if(encryption_params_obj.isNull()) {
        CLIENT_LOG_ERROR("Encryption parameters not found in response");
        err = std::string("Failed to get encryption parameters from response.");
        return false;
    }

    std::string block_mode_str = encryption_params_obj.get(JSON_RESPONSE_BLOCK_MODE_KEY,
                                                           "").asString();
    if(block_mode_str.empty()) {
        CLIENT_LOG_ERROR("Block mode not found encryption parameters");
        err = std::string("Failed to get block mode from encryption parameters");
        return false;
    }

    BlockCipherMode block_mode;
    if(!toNative(block_mode_str, block_mode)) {
        CLIENT_LOG_ERROR("Unsupported block mode");
        err = std::string("Unsupported block mode:") + block_mode_str;
        return false;
    }

    std::string block_padding_str = encryption_params_obj.get(JSON_RESPONSE_BLOCK_PADDING_KEY,
                                                              "").asString();
    if(block_padding_str.empty()) {
        CLIENT_LOG_ERROR("Block padding not found encryption parameters");
        err = std::string("Failed to get block padding from encryption parameters");
        return false;
    }

    BlockCipherPadding block_padding;
    if(!toNative(block_padding_str, block_padding)) {
        CLIENT_LOG_ERROR("Unsupported block padding");
        err = std::string("Unsupported block padding:") + block_padding_str;
        return false;
    }

    std::string cipher_str = encryption_params_obj.get(JSON_RESPONSE_CIPHER_KEY,
                                                       "").asString();
    if(cipher_str.empty()) {
        CLIENT_LOG_ERROR("Cipher algorithm not found encryption parameters");
        err = std::string("Failed to get cipher algorithm from encryption parameters");
        return false;
    }

    CipherAlgorithm cipher;
    if(!toNative(cipher_str, cipher)) {
        CLIENT_LOG_ERROR("Unsupported cipher algorithm");
        err = std::string("Unsupported cipher algorithm:") + cipher_str;
        return false;
    }

    size_t key_bits = static_cast<size_t>(encryption_params_obj.get(JSON_RESPONSE_BLOCK_KEY_SIZE_KEY,
                                                                   0).asInt());
    if(key_bits == 0) {
        CLIENT_LOG_ERROR("Failed to get key bits from encryption parameters");
        err = std::string("Failed to get key bits from encryption parameters");
        return false;
    }

    std::string iv_str = encryption_params_obj.get(JSON_RESPONSE_IV_KEY, "").asString();
    if(iv_str.empty()) {
        CLIENT_LOG_ERROR("Failed to get iv from encryption parameters");
        err = std::string("Failed to get iv from encryption parameters");
        return false;
    }

    std::string authentication_data_str = json_obj.get(JSON_RESPONSE_AUTHENTICATION_DATA_KEY,
                                                       "").asString();
    if(authentication_data_str.empty()) {
        CLIENT_LOG_ERROR("Failed to get authentication data response");
        err = std::string("Failed to get authentication data response");
        return false;
    }

    encryption_params.iv = attest::base64::
                                   base64_to_binary(iv_str);
    encryption_params.authentication_data = attest::base64::
                                                    base64_to_binary(authentication_data_str);
    encryption_params.block_mode = block_mode;
    encryption_params.block_padding = block_padding;
    encryption_params.cipher_alg = cipher;
    encryption_params.key_size = key_bits;

    return true;
}

bool attest::GetEncryptedJwt(const Json::Value& json_obj,
                             attest::Buffer& jwt_encrypted,
                             std::string& err) {

    err.clear();

    std::string jwt_encrypted_str = json_obj.get(JSON_RESPONSE_JWT_KEY,
                                                 "").asString();
    if(jwt_encrypted_str.empty()) {
        CLIENT_LOG_ERROR("Failed to get jwt from response.");
        err = std::string("Failed to get jwt from response.");
        return false;
    }
    jwt_encrypted = attest::base64::
                            base64_to_binary(jwt_encrypted_str);
    return true;
}

attest::AttestationResult attest::DecryptInnerKey(const attest::Buffer& encrypted_inner_key,
                                                  attest::Buffer& decrypted_key) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

    try {

        Tpm tpm;

        attest::PcrList list = GetAttestationPcrList();

        attest::PcrSet pcrValues = tpm.GetPCRValues(list, attestation_hash_alg);

        decrypted_key = tpm.DecryptWithEphemeralKey(pcrValues, encrypted_inner_key);
    }
    catch(const Tss2Exception& e) {
        // Since tss2 errors are throw Tss2Exception exception. Catch it here.
        result.code_ = AttestationResult::ErrorCode::ERROR_JWT_DECRYPTION_TPM_ERROR;
        result.tpm_error_code_ = e.get_rc();
        result.description_ = std::string(e.what());

        CLIENT_LOG_ERROR("Failed Tpm operation:%d Error:%s",
                          result.tpm_error_code_,
                          result.description_.c_str());
        return result;
    }
    catch(const std::exception& e) {
        // Since tss2 errors are throw runtime error exception. Catch it here.
        result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
        result.description_ = std::string(e.what());

        CLIENT_LOG_ERROR("Tpm internal error:%s",
                          result.description_.c_str());
        return result;
    }
    catch(...) {
        // Unknown exception.
        result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
        result.description_ = std::string("Error: Unknown internal error");

        CLIENT_LOG_ERROR("Tpm internal error:%s",
                          result.description_.c_str());
        return result;
    }
    return result;
}

static const EVP_CIPHER* _GetOpenSslAesGcmAlg(size_t keyLen) {
    switch (keyLen)
    {
        case 128 / 8:
            return EVP_aes_128_gcm();
        case 192 / 8:
            return EVP_aes_192_gcm();
        case 256 / 8:
            return EVP_aes_256_gcm();
        default:
            return nullptr;
    }
}

bool attest::DecryptJwt(const EncryptionParameters& encryption_params,
                        const attest::Buffer& decryption_key,
                        const attest::Buffer& jwt_encrypted,
                        std::string& jwt_decrypted,
                        std::string& err) {
    err.clear();

    if(encryption_params.block_mode != attest::BlockCipherMode::CHAINING_MODE_GCM) {
        CLIENT_LOG_ERROR("Unsupported block mode");
        err = std::string("Error: Unsupported block mode");
        return false;
    }
    if(encryption_params.block_padding != attest::BlockCipherPadding::PKCS7) {
        CLIENT_LOG_ERROR("Unsupported block padding");
        err = std::string("Error: Unsupported block padding");
        return false;
    }
    if(encryption_params.cipher_alg != attest::CipherAlgorithm::AES) {
        CLIENT_LOG_ERROR("Unsupported decryption algorithm");
        err = std::string("Error: Unsupported decryption algorithm");
        return false;
    }

    EVP_CIPHER_CTX *ctx;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        CLIENT_LOG_ERROR("Openssl Error: Failed to initialize evp cipher");
        err = std::string("Openssl Error: Failed to initialize evp cipher");
        return false;
    }

    const EVP_CIPHER* alg = _GetOpenSslAesGcmAlg(decryption_key.size());
    if(alg == nullptr) {
        CLIENT_LOG_ERROR("Openssl Error: Failed to get decryption algorithm");
        err = std::string("Openssl Error: Failed to get decryption algorithm");
        return false;
    }

    //Initialise the decryption operation.
    if(!EVP_DecryptInit_ex(ctx, alg, NULL, NULL, NULL)) {
        std::string error_str(ERR_error_string(ERR_get_error(), nullptr));
        CLIENT_LOG_ERROR("Openssl Error:%s", error_str.c_str());
        err = std::string("Openssl Error:") + error_str;
        return false;
    }

    // Set IV length. Not necessary if this is 12 bytes (96 bits)
    if(!EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(encryption_params.iv.size()),
                            NULL)) {
        std::string error_str(ERR_error_string(ERR_get_error(), nullptr));
        CLIENT_LOG_ERROR("Openssl Error:%s", error_str.c_str());
        err = std::string("Openssl Error:") + error_str;
        return false;
    }

    // Initialise key and IV
    if(!EVP_DecryptInit_ex(ctx,
                           NULL,
                           NULL,
                           decryption_key.data(),
                           encryption_params.iv.data())) {
        std::string error_str(ERR_error_string(ERR_get_error(), nullptr));
        CLIENT_LOG_ERROR("Openssl Error:%s", error_str.c_str());
        err = std::string("Openssl Error:") + error_str;
        return false;
    }

    attest::Buffer auth_data{'T','r','a','n','s','p','o','r','t',' ','K','e','y'};
    int out_bytes = 0;
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
    */
    if(!EVP_DecryptUpdate(ctx,
                          NULL,
                          &out_bytes,
                          auth_data.data(),
                          static_cast<int>(auth_data.size()))) {
        std::string error_str(ERR_error_string(ERR_get_error(), nullptr));
        CLIENT_LOG_ERROR("Openssl Error:%s", error_str.c_str());;
        err = std::string("Openssl Error:") + error_str;
        return false;
    }

    attest::Buffer plain_text(jwt_encrypted.size());

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(!EVP_DecryptUpdate(ctx,
                          plain_text.data(),
                          &out_bytes,
                          (const unsigned char*)jwt_encrypted.data(),
                          static_cast<int>(jwt_encrypted.size()))) {
        std::string error_str(ERR_error_string(ERR_get_error(), nullptr));
        CLIENT_LOG_ERROR("Openssl Error:%s", error_str.c_str());
        err = std::string("Openssl Error:") + error_str;
        return false;
    }

    // Set expected tag value. Works in OpenSSL 1.0.1d and later
    if(!EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(encryption_params.authentication_data.size()),
                            (void *)encryption_params.authentication_data.data())) {
        std::string error_str(ERR_error_string(ERR_get_error(), nullptr));
        CLIENT_LOG_ERROR("Openssl Error:%s", error_str.c_str());
        err = std::string("Openssl Error:") + error_str;
        return false;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    int ret = EVP_DecryptFinal_ex(ctx,
                                  plain_text.data(),
                                  &out_bytes);
    if(ret <= 0) {
        std::string error_str(ERR_error_string(ERR_get_error(), nullptr));
        CLIENT_LOG_ERROR("Openssl Error:%s", error_str.c_str());
        err = std::string("Openssl Error:") + error_str;
        return false;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    jwt_decrypted.assign(plain_text.begin(), plain_text.end());
    return true;
}

bool attest::GetEncryptedInnerKey(const Json::Value& json_obj,
                                  attest::Buffer& encrypted_inner_key,
                                  std::string& err) {
    err.clear();

    std::string encrypted_inner_key_str = json_obj.get(JSON_RESPONSE_ENC_INNER_KEY_KEY,
                                                       "").asString();
    if(encrypted_inner_key_str.empty()) {
        CLIENT_LOG_ERROR("Failed to get encrypted inner key from response.");
        err = std::string("Failed to get encrypted inner key from response.");
        return false;
    }

    encrypted_inner_key = attest::base64::
                            base64_to_binary(encrypted_inner_key_str);
    return true;
}